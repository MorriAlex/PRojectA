import sqlite3
import os
import shutil
from datetime import datetime
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox

class SecurityManager:
    """Полная эмуляция подсистемы безопасности серверной СУБД."""
    def __init__(self):
        self.users = {}          
        self.roles = {}          
        self.current_user = None 

    def create_user(self, login, password, role):
        """CREATE USER."""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.users[login] = {'password_hash': password_hash, 'role': role}

    def authenticate(self, login, password):
        """Проверка учётных данных."""
        if login not in self.users:
            return False
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return self.users[login]['password_hash'] == password_hash

    def set_current_user(self, login):
        """Установка текущего пользователя (сессия)."""
        if login in self.users:
            self.current_user = login
            return True
        return False

    def get_current_role(self):
        """Роль текущего пользователя."""
        if self.current_user:
            return self.users[self.current_user]['role']
        return None

    def grant_privilege(self, role, table, operation):
        """GRANT привилегии роли."""
        if role not in self.roles:
            self.roles[role] = set()
        self.roles[role].add((table, operation))

    def check_privilege(self, table, operation):
        """Проверка, разрешена ли операция текущему пользователю."""
        if not self.current_user:
            return False
        role = self.users[self.current_user]['role']
        if role == 'admin':   
            return True
        if role not in self.roles:
            return False
        privs = self.roles[role]
        if ('*', operation) in privs or ('*', '*') in privs:
            return True
        return (table, operation) in privs


sec = SecurityManager()

DB_FILE = "ProjectManagement.db"
BACKUP_DIR = "backups"
os.makedirs(BACKUP_DIR, exist_ok=True)

def get_connection():
    """Создание соединения с БД."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def set_session_user(conn, username):
    """Устанавливает текущего пользователя в сессии БД (для триггеров)."""
    conn.execute("DELETE FROM session;")
    conn.execute("INSERT INTO session (id, current_user) VALUES (1, ?);", (username,))
    conn.commit()

def execute_query(conn, sql, params=(), table=None, operation=None, skip_privilege_check=False):
    """
    Выполняет SQL-запрос с предварительной проверкой прав.
    Если skip_privilege_check=True, проверка пропускается (для инициализации).
    Если table и operation указаны – проверяет привилегию.
    Возвращает курсор.
    """
    if not skip_privilege_check and table and operation:
        if not sec.check_privilege(table, operation):
            raise PermissionError(
                f"Access denied: user '{sec.current_user}' cannot {operation} on table '{table}'"
            )
    cursor = conn.cursor()
    cursor.execute(sql, params)
    conn.commit()
    return cursor

def init_database():
    """Надёжное создание БД: если файла нет ИЛИ он не содержит таблиц – создаёт заново."""
    db_ok = False
    if os.path.exists(DB_FILE):
        try:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='employees';")
            if cur.fetchone():
                db_ok = True
            conn.close()
        except sqlite3.Error:
            db_ok = False

    if not db_ok:
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        print("Создание новой базы данных ProjectManagement.db...")
    else:
        print("База данных уже существует и содержит таблицы. Пропускаем инициализацию.")
        return

    conn = get_connection()

    execute_query(conn, """
    CREATE TABLE employees (
        employee_id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        position TEXT,
        hire_date DATE NOT NULL,
        mysql_user TEXT
    );
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TABLE projects (
        project_id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_name TEXT NOT NULL,
        start_date DATE,
        end_date DATE,
        status TEXT CHECK (status IN ('active', 'completed', 'onhold')) DEFAULT 'active'
    );
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TABLE tasks (
        task_id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        task_name TEXT NOT NULL,
        description TEXT,
        deadline DATE,
        status TEXT CHECK (status IN ('new', 'in_progress', 'done')) DEFAULT 'new',
        FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
    );
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TABLE assignments (
        assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        employee_id INTEGER NOT NULL,
        assigned_date DATE NOT NULL,
        hours_estimated DECIMAL(5,2),
        FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
        FOREIGN KEY (employee_id) REFERENCES employees(employee_id) ON DELETE CASCADE,
        CHECK (hours_estimated > 0)
    );
    """, skip_privilege_check=True)

    execute_query(conn, """
    CREATE TABLE audit_log (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        table_name TEXT NOT NULL,
        operation TEXT NOT NULL,
        old_data TEXT,
        new_data TEXT,
        changed_by TEXT NOT NULL,
        changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TABLE task_status_history (
        history_id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        old_status TEXT,
        new_status TEXT,
        changed_by TEXT,
        changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
    );
    """, skip_privilege_check=True)

    execute_query(conn, """
    CREATE TABLE IF NOT EXISTS session (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        current_user TEXT NOT NULL
    );
    """, skip_privilege_check=True)
    execute_query(conn, "INSERT OR IGNORE INTO session (id, current_user) VALUES (1, 'system');", skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_after_insert
    AFTER INSERT ON tasks
    BEGIN
        INSERT INTO audit_log (table_name, operation, new_data, changed_by)
        VALUES ('tasks', 'INSERT',
                json_object('task_id', NEW.task_id, 'task_name', NEW.task_name, 'status', NEW.status),
                (SELECT current_user FROM session WHERE id = 1));
    END;
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_after_update
    AFTER UPDATE ON tasks
    BEGIN
        INSERT INTO audit_log (table_name, operation, old_data, new_data, changed_by)
        VALUES ('tasks', 'UPDATE',
                json_object('task_id', OLD.task_id, 'task_name', OLD.task_name, 'status', OLD.status),
                json_object('task_id', NEW.task_id, 'task_name', NEW.task_name, 'status', NEW.status),
                (SELECT current_user FROM session WHERE id = 1));
    END;
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_after_delete
    AFTER DELETE ON tasks
    BEGIN
        INSERT INTO audit_log (table_name, operation, old_data, changed_by)
        VALUES ('tasks', 'DELETE',
                json_object('task_id', OLD.task_id, 'task_name', OLD.task_name, 'status', OLD.status),
                (SELECT current_user FROM session WHERE id = 1));
    END;
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS projects_before_update
    BEFORE UPDATE ON projects
    WHEN NEW.status = 'completed' AND OLD.status != 'completed'
    BEGIN
        SELECT RAISE(ABORT, 'Cannot complete project: there are unfinished tasks')
        WHERE EXISTS (SELECT 1 FROM tasks WHERE project_id = NEW.project_id AND status != 'done');
    END;
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_status_update
    AFTER UPDATE ON tasks
    WHEN OLD.status != NEW.status
    BEGIN
        INSERT INTO task_status_history (task_id, old_status, new_status, changed_by)
        VALUES (NEW.task_id, OLD.status, NEW.status, (SELECT current_user FROM session WHERE id = 1));
    END;
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS assignments_before_insert
    BEFORE INSERT ON assignments
    BEGIN
        SELECT RAISE(ABORT, 'Employees can only assign tasks to themselves')
        WHERE NOT EXISTS (
            SELECT 1 FROM employees 
            WHERE employee_id = NEW.employee_id 
            AND mysql_user = (SELECT current_user FROM session WHERE id = 1)
        )
        AND (SELECT current_user FROM session WHERE id = 1) NOT IN ('alex_admin', 'maria_manager');
    END;
    """, skip_privilege_check=True)
     
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS assignments_before_update
    BEFORE UPDATE ON assignments
    BEGIN
        SELECT RAISE(ABORT, 'Employees can only update their own assignments')
        WHERE NOT EXISTS (
            SELECT 1 FROM employees 
            WHERE employee_id = NEW.employee_id 
            AND mysql_user = (SELECT current_user FROM session WHERE id = 1)
        )
        AND (SELECT current_user FROM session WHERE id = 1) NOT IN ('alex_admin', 'maria_manager');
    END;
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS employees_before_insert_update
    BEFORE INSERT ON employees
    BEGIN
        SELECT RAISE(ABORT, 'Hire date cannot be in the future')
        WHERE NEW.hire_date > date('now');
    END;
    """, skip_privilege_check=True)
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS employees_before_update
    BEFORE UPDATE ON employees
    BEGIN
        SELECT RAISE(ABORT, 'Hire date cannot be in the future')
        WHERE NEW.hire_date > date('now');
    END;
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_before_insert_update
    BEFORE INSERT ON tasks
    BEGIN
        SELECT RAISE(ABORT, 'Deadline cannot be in the past')
        WHERE NEW.deadline IS NOT NULL AND NEW.deadline < date('now');
    END;
    """, skip_privilege_check=True)
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_before_update
    BEFORE UPDATE ON tasks
    BEGIN
        SELECT RAISE(ABORT, 'Deadline cannot be in the past')
        WHERE NEW.deadline IS NOT NULL AND NEW.deadline < date('now');
    END;
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS assignments_before_insert_update
    BEFORE INSERT ON assignments
    BEGIN
        SELECT RAISE(ABORT, 'Assigned date cannot be in the future')
        WHERE NEW.assigned_date > date('now');
    END;
    """, skip_privilege_check=True)
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS assignments_before_update_date
    BEFORE UPDATE ON assignments
    BEGIN
        SELECT RAISE(ABORT, 'Assigned date cannot be in the future')
        WHERE NEW.assigned_date > date('now');
    END;
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    INSERT INTO employees (full_name, email, position, hire_date, mysql_user) VALUES
    ('Иван Петров', 'ivan.petrov@example.com', 'Разработчик', '2023-01-15', 'ivan_employee'),
    ('Елена Смирнова', 'elena.smirnova@example.com', 'Тестировщик', '2023-03-20', 'elena_employee'),
    ('Алексей Иванов', 'alex.ivanov@example.com', 'Менеджер', '2022-11-01', NULL);
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    INSERT INTO projects (project_name, start_date, status) VALUES
    ('Разработка CRM', '2025-01-10', 'active'),
    ('Мобильное приложение', '2025-02-01', 'active');
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    INSERT INTO tasks (project_id, task_name, deadline, status) VALUES
    (1, 'Проектирование БД', '2026-03-01', 'done'),
    (1, 'Разработка API', '2026-04-01', 'in_progress'),
    (2, 'Дизайн интерфейса', '2026-03-15', 'new');
    """, skip_privilege_check=True)
    
    execute_query(conn, "UPDATE session SET current_user = 'alex_admin' WHERE id = 1;", skip_privilege_check=True)
    
    execute_query(conn, """
    INSERT INTO assignments (task_id, employee_id, assigned_date, hours_estimated) VALUES
    (1, 1, '2025-01-20', 40.0),
    (2, 1, '2025-02-10', 80.0),
    (3, 2, '2025-02-15', 30.0);
    """, skip_privilege_check=True)
    
    conn.close()
    print("✓ База данных успешно создана и наполнена тестовыми данными.")


def setup_security_policy():
    """Инициализация ролей, пользователей и привилегий в эмуляторе."""
    tables = ['projects', 'tasks', 'employees', 'assignments']
    for tbl in tables:
        sec.grant_privilege('manager', tbl, 'SELECT')
        sec.grant_privilege('manager', tbl, 'INSERT')
        sec.grant_privilege('manager', tbl, 'UPDATE')
    sec.grant_privilege('manager', 'assignments', 'DELETE')
    
    sec.grant_privilege('employee', 'tasks', 'SELECT')
    sec.grant_privilege('employee', 'projects', 'SELECT')
    sec.grant_privilege('employee', 'assignments', 'SELECT')
    sec.grant_privilege('employee', 'employees', 'SELECT')
    sec.grant_privilege('employee', 'assignments', 'INSERT')
    sec.grant_privilege('employee', 'assignments', 'UPDATE')

    sec.create_user('alex_admin', 'SecurePass123', 'admin')
    sec.create_user('maria_manager', 'ManagerPass456', 'manager')
    sec.create_user('ivan_employee', 'EmployeePass789', 'employee')
    sec.create_user('elena_employee', 'EmployeePass000', 'employee')


def get_employee_id_by_user(username):
    """Возвращает employee_id для заданного mysql_user или None."""
    conn = get_connection()
    cur = conn.execute("SELECT employee_id FROM employees WHERE mysql_user = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row['employee_id'] if row else None

def backup_database():
    """Создание резервной копии файла БД."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = os.path.join(BACKUP_DIR, f'ProjectManagement_backup_{timestamp}.db')
    shutil.copy2(DB_FILE, backup_file)
    return backup_file

def list_backups():
    """Возвращает список файлов резервных копий."""
    files = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.db')]
    files.sort(reverse=True)
    return files

def restore_database(backup_filename):
    """Восстановление БД из резервной копии."""
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    if os.path.exists(backup_path):
        shutil.copy2(backup_path, DB_FILE)
        return True
    return False

class LoginWindow(tk.Toplevel):
    """Окно аутентификации с отображением паролей."""
    def __init__(self, master, on_success):
        super().__init__(master)
        self.title("Вход в систему безопасности БД")
        self.geometry("400x350")
        self.resizable(False, False)
        self.configure(bg='#f0f0f0')
        self.on_success = on_success
        
        # Основной контейнер
        main_frame = tk.Frame(self, bg='#f0f0f0', padx=30, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Заголовок
        title_label = tk.Label(main_frame, text="Аутентификация", 
                               font=('Arial', 16, 'bold'),
                               bg='#f0f0f0', fg='#333333')
        title_label.pack(pady=(0, 20))
        
        # Форма входа
        form_frame = tk.Frame(main_frame, bg='#f0f0f0')
        form_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(form_frame, text="Пользователь:", 
                bg='#f0f0f0', font=('Arial', 10)).pack(anchor=tk.W)
        
        self.user_var = tk.StringVar()
        self.user_combo = ttk.Combobox(form_frame, textvariable=self.user_var, 
                                       state='readonly', font=('Arial', 10))
        self.user_combo['values'] = ('alex_admin', 'maria_manager', 'ivan_employee', 'elena_employee')
        self.user_combo.current(0)
        self.user_combo.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(form_frame, text="Пароль:", 
                bg='#f0f0f0', font=('Arial', 10)).pack(anchor=tk.W)
        
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(form_frame, textvariable=self.pass_var, 
                                    show='*', font=('Arial', 10))
        self.pass_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Кнопка входа
        self.btn_login = tk.Button(form_frame, text="ВОЙТИ", 
                                   bg='#4CAF50', fg='white',
                                   font=('Arial', 11, 'bold'),
                                   padx=20, pady=8,
                                   command=self.login)
        self.btn_login.pack(pady=10)
        
        # Информационная панель
        info_frame = tk.Frame(main_frame, bg='#e0e0e0', relief=tk.GROOVE, bd=1)
        info_frame.pack(fill=tk.X, pady=10)
        
        info_text = (
            "Учётные записи:\n"
            "────────────────\n"
            "alex_admin    / SecurePass123"
        )
        tk.Label(info_frame, text=info_text, justify=tk.LEFT, 
                font=('Consolas', 9), bg='#e0e0e0', padx=10, pady=10).pack()
        
        self.bind('<Return>', lambda e: self.login())
        self.pass_entry.focus()
        
    def login(self):
        username = self.user_var.get()
        password = self.pass_var.get()
        if sec.authenticate(username, password):
            sec.set_current_user(username)
            self.destroy()
            self.on_success(username)
        else:
            messagebox.showerror("Ошибка", "Неверный логин или пароль")
            self.pass_var.set("")


class MainWindow(tk.Tk):
    """Главное окно приложения."""
    def __init__(self):
        super().__init__()
        self.title("Система защиты БД «Управление проектами»")
        self.geometry("1000x650")
        self.configure(bg='#f0f0f0')
        self.current_user = None
        self.current_employee_id = None

        init_database()
        setup_security_policy()
        
        self.withdraw()
        LoginWindow(self, self.on_login_success)
        
    def on_login_success(self, username):
        """Колбэк после успешного входа."""
        self.current_user = username
        self.current_employee_id = get_employee_id_by_user(username)
        
        for widget in self.winfo_children():
            widget.destroy()
        
        self.deiconify()
        self.create_widgets()
        self.refresh_table_list()
        
    def create_widgets(self):
        """Создание элементов интерфейса."""
        # Верхняя панель с информацией о пользователе
        top_frame = tk.Frame(self, bg='#d9d9d9', relief=tk.RAISED, bd=1, height=50)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        top_frame.pack_propagate(False)
        
        role = sec.get_current_role()
        user_info = tk.Label(top_frame, 
                            text=f"👤 {self.current_user} (роль: {role})",
                            font=('Arial', 11, 'bold'),
                            bg='#d9d9d9', fg='#333333')
        user_info.pack(side=tk.LEFT, padx=15)
        
        # Кнопки управления справа
        btn_frame = tk.Frame(top_frame, bg='#d9d9d9')
        btn_frame.pack(side=tk.RIGHT, padx=10)
        
        tk.Button(btn_frame, text="🔄 Сменить пользователя", 
                 bg='#2196F3', fg='white',
                 font=('Arial', 9), padx=10,
                 command=self.logout).pack(side=tk.LEFT, padx=2)
        
        tk.Button(btn_frame, text="✕ Выход", 
                 bg='#f44336', fg='white',
                 font=('Arial', 9), padx=10,
                 command=self.quit_app).pack(side=tk.LEFT, padx=2)
        
        # Блокнот с вкладками
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#f0f0f0')
        style.configure('TNotebook.Tab', background='#e0e0e0', padding=[10, 2])
        style.map('TNotebook.Tab', background=[('selected', '#f0f0f0')])
        
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Вкладки
        self.tab_tables = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.tab_tables, text="📊 Таблицы")
        self.setup_tables_tab()
        
        self.tab_audit = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.tab_audit, text="📝 Аудит")
        self.setup_audit_tab()
        
        self.tab_backup = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.tab_backup, text="💾 Резервное копирование")
        self.setup_backup_tab()
        
        self.tab_test = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.tab_test, text="🧪 Тестирование")
        self.setup_test_tab()
        
    def setup_tables_tab(self):
        """Настройка интерфейса для работы с таблицами."""
        # Верхняя панель управления
        control_frame = tk.Frame(self.tab_tables, bg='#e8e8e8', height=60, relief=tk.GROOVE, bd=1)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        control_frame.pack_propagate(False)
        
        # Выбор таблицы слева
        table_frame = tk.Frame(control_frame, bg='#e8e8e8')
        table_frame.pack(side=tk.LEFT, padx=15, pady=10)
        
        tk.Label(table_frame, text="Таблица:", bg='#e8e8e8', 
                font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=(0,5))
        
        self.table_var = tk.StringVar()
        self.table_combo = ttk.Combobox(table_frame, textvariable=self.table_var, 
                                        state='readonly', width=15)
        self.table_combo['values'] = ('employees', 'projects', 'tasks', 'assignments')
        self.table_combo.current(0)
        self.table_combo.pack(side=tk.LEFT)
        self.table_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_table_view())
        
        # Кнопки операций справа
        btn_frame = tk.Frame(control_frame, bg='#e8e8e8')
        btn_frame.pack(side=tk.RIGHT, padx=15, pady=8)
        
        self.btn_refresh = tk.Button(btn_frame, text="🔄 Обновить", 
                                     bg='#607d8b', fg='white',
                                     font=('Arial', 9), padx=10,
                                     command=self.refresh_table_view)
        self.btn_refresh.pack(side=tk.LEFT, padx=2)
        
        self.btn_add = tk.Button(btn_frame, text="➕ Добавить", 
                                bg='#4CAF50', fg='white',
                                font=('Arial', 9), padx=10,
                                command=self.add_record)
        self.btn_add.pack(side=tk.LEFT, padx=2)
        
        self.btn_edit = tk.Button(btn_frame, text="✏️ Изменить", 
                                  bg='#ff9800', fg='white',
                                  font=('Arial', 9), padx=10,
                                  command=self.edit_record)
        self.btn_edit.pack(side=tk.LEFT, padx=2)
        
        self.btn_delete = tk.Button(btn_frame, text="🗑️ Удалить", 
                                    bg='#f44336', fg='white',
                                    font=('Arial', 9), padx=10,
                                    command=self.delete_record)
        self.btn_delete.pack(side=tk.LEFT, padx=2)
        
        # Основная область с таблицей
        table_container = tk.Frame(self.tab_tables, bg='#f0f0f0')
        table_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        
        # Таблица данных
        columns_frame = tk.Frame(table_container, bg='white', relief=tk.SUNKEN, bd=1)
        columns_frame.pack(fill=tk.BOTH, expand=True)
        
        v_scroll = ttk.Scrollbar(columns_frame, orient=tk.VERTICAL)
        h_scroll = ttk.Scrollbar(columns_frame, orient=tk.HORIZONTAL)
        
        self.tree = ttk.Treeview(columns_frame, 
                                 yscrollcommand=v_scroll.set,
                                 xscrollcommand=h_scroll.set,
                                 selectmode='browse',
                                 height=15)
        
        v_scroll.config(command=self.tree.yview)
        h_scroll.config(command=self.tree.xview)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        v_scroll.grid(row=0, column=1, sticky='ns')
        h_scroll.grid(row=1, column=0, sticky='ew')
        
        columns_frame.grid_rowconfigure(0, weight=1)
        columns_frame.grid_columnconfigure(0, weight=1)
        
        # Информационная строка
        info_bar = tk.Frame(self.tab_tables, bg='#e0e0e0', height=25, relief=tk.SUNKEN, bd=1)
        info_bar.pack(fill=tk.X, padx=10, pady=(0,5))
        info_bar.pack_propagate(False)
        
        self.status_label = tk.Label(info_bar, text="Записей: 0", 
                                     bg='#e0e0e0', anchor=tk.W, padx=10)
        self.status_label.pack(fill=tk.BOTH, expand=True)
        
        self.refresh_table_list()
        
    def refresh_table_list(self):
        """Обновляет список доступных таблиц в зависимости от прав."""
        table = self.table_var.get()
        self.refresh_table_view()
        
    def refresh_table_view(self):
        """Загружает данные из выбранной таблицы в Treeview."""
        table = self.table_var.get()
        if not table:
            return
        
        self.tree.delete(*self.tree.get_children())
        
        conn = get_connection()
        set_session_user(conn, self.current_user)
        
        try:
            if table == 'assignments' and sec.get_current_role() == 'employee' and self.current_employee_id:
                cur = conn.execute(
                    "SELECT * FROM assignments WHERE employee_id = ?",
                    (self.current_employee_id,)
                )
            else:
                cur = conn.execute(f"SELECT * FROM {table} LIMIT 100")
            
            rows = cur.fetchall()
            if rows:
                columns = list(rows[0].keys())
                self.tree['columns'] = columns
                self.tree['show'] = 'headings'
                for col in columns:
                    self.tree.heading(col, text=col)
                    self.tree.column(col, width=100, anchor=tk.CENTER)
                
                for row in rows:
                    values = [row[col] for col in columns]
                    self.tree.insert('', tk.END, values=values)
                
                self.status_label.config(text=f"Записей: {len(rows)}")
            else:
                self.status_label.config(text="Записей: 0")
        except sqlite3.Error as e:
            messagebox.showerror("Ошибка БД", str(e))
        finally:
            conn.close()
        
        self.update_button_states()
    
    def update_button_states(self):
        """Включает/выключает кнопки в соответствии с привилегиями."""
        table = self.table_var.get()
        if sec.check_privilege(table, 'INSERT'):
            self.btn_add.config(state=tk.NORMAL)
        else:
            self.btn_add.config(state=tk.DISABLED)
        if sec.check_privilege(table, 'UPDATE'):
            self.btn_edit.config(state=tk.NORMAL)
        else:
            self.btn_edit.config(state=tk.DISABLED)
        if sec.check_privilege(table, 'DELETE'):
            self.btn_delete.config(state=tk.NORMAL)
        else:
            self.btn_delete.config(state=tk.DISABLED)
    
    def get_selected_row(self):
        """Возвращает словарь с данными выделенной строки или None."""
        selection = self.tree.selection()
        if not selection:
            return None
        item = selection[0]
        values = self.tree.item(item, 'values')
        columns = self.tree['columns']
        return dict(zip(columns, values))
    
    def add_record(self):
        """Добавление новой записи."""
        table = self.table_var.get()
        if table == 'assignments' and sec.get_current_role() == 'employee':
            if not self.current_employee_id:
                messagebox.showerror("Ошибка", "Ваш профиль сотрудника не найден")
                return
            self.show_add_edit_dialog(table, mode='add', default_emp_id=self.current_employee_id)
        else:
            self.show_add_edit_dialog(table, mode='add')
    
    def edit_record(self):
        """Изменение существующей записи."""
        table = self.table_var.get()
        row_data = self.get_selected_row()
        if not row_data:
            messagebox.showinfo("Информация", "Выберите запись для изменения")
            return
        self.show_add_edit_dialog(table, mode='edit', initial_data=row_data)
    
    def delete_record(self):
        """Удаление записи."""
        table = self.table_var.get()
        row_data = self.get_selected_row()
        if not row_data:
            messagebox.showinfo("Информация", "Выберите запись для удаления")
            return
        
        pk_column = {
            'employees': 'employee_id',
            'projects': 'project_id',
            'tasks': 'task_id',
            'assignments': 'assignment_id'
        }.get(table)
        
        if not pk_column or pk_column not in row_data:
            messagebox.showerror("Ошибка", "Не удалось определить первичный ключ")
            return
        
        pk_value = row_data[pk_column]
        
        if not messagebox.askyesno("Подтверждение", f"Удалить запись с {pk_column}={pk_value}?"):
            return
        
        conn = get_connection()
        set_session_user(conn, self.current_user)
        try:
            execute_query(conn, f"DELETE FROM {table} WHERE {pk_column} = ?",
                         (pk_value,), table=table, operation='DELETE')
            messagebox.showinfo("Успех", "Запись удалена")
            self.refresh_table_view()
        except (sqlite3.Error, PermissionError) as e:
            messagebox.showerror("Ошибка", str(e))
        finally:
            conn.close()
    
    def show_add_edit_dialog(self, table, mode='add', initial_data=None, default_emp_id=None):
        """Диалог для добавления/редактирования записи."""
        dialog = tk.Toplevel(self)
        dialog.title("Добавление записи" if mode == 'add' else "Редактирование записи")
        dialog.geometry("600x500")
        dialog.configure(bg='#f0f0f0')
        dialog.transient(self)
        dialog.grab_set()
        
        # Заголовок
        title_frame = tk.Frame(dialog, bg='#2196F3', height=40)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        title_text = "➕ Добавление новой записи" if mode == 'add' else "✏️ Редактирование записи"
        tk.Label(title_frame, text=title_text, 
                bg='#2196F3', fg='white',
                font=('Arial', 12, 'bold')).pack(expand=True)
        
        # Форма
        form_frame = tk.Frame(dialog, bg='#f0f0f0', padx=20, pady=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        conn = get_connection()
        cur = conn.execute(f"PRAGMA table_info({table})")
        columns_info = cur.fetchall()
        conn.close()
        
        entries = {}
        row_num = 0
        for col_info in columns_info:
            col_name = col_info[1]
            col_type = col_info[2]
            not_null = col_info[3]
            pk = col_info[5]
            
            if mode == 'add' and pk and col_info[4] == 1:  
                continue
            
            # Контейнер для поля
            field_frame = tk.Frame(form_frame, bg='#f0f0f0')
            field_frame.pack(fill=tk.X, pady=5)
            
            label_text = f"{col_name} ({col_type}):"
            if not_null:
                label_text += " *"
            
            tk.Label(field_frame, text=label_text, 
                    bg='#f0f0f0', font=('Arial', 9, 'bold'),
                    width=20, anchor=tk.W).pack(side=tk.LEFT)
            
            var = tk.StringVar()
            if initial_data and col_name in initial_data:
                var.set(initial_data[col_name])
            if mode == 'add' and table == 'assignments' and col_name == 'employee_id' and default_emp_id:
                var.set(str(default_emp_id))
                entry = ttk.Entry(field_frame, textvariable=var, state='readonly', width=30)
            else:
                entry = ttk.Entry(field_frame, textvariable=var, width=30)
            
            entry.pack(side=tk.LEFT, padx=5)
            entries[col_name] = var
            row_num += 1
        
        # Кнопки
        btn_frame = tk.Frame(dialog, bg='#e0e0e0', height=50)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)
        btn_frame.pack_propagate(False)
        
        tk.Button(btn_frame, text="Сохранить", 
                 bg='#4CAF50', fg='white',
                 font=('Arial', 10, 'bold'),
                 padx=20, pady=5,
                 command=lambda: self.save_record(dialog, table, mode, entries, initial_data)).pack(side=tk.RIGHT, padx=10)
        
        tk.Button(btn_frame, text="Отмена", 
                 bg='#9e9e9e', fg='white',
                 font=('Arial', 10),
                 padx=20, pady=5,
                 command=dialog.destroy).pack(side=tk.RIGHT, padx=10)
    
    def save_record(self, dialog, table, mode, entries, initial_data=None):
        """Сохранение записи из диалога."""
        cols = []
        placeholders = []
        values = []
        for col_name, var in entries.items():
            val = var.get().strip()
            if not val:
                messagebox.showerror("Ошибка", f"Поле {col_name} обязательно")
                return
            cols.append(col_name)
            placeholders.append('?')
            values.append(val)
        
        conn = get_connection()
        set_session_user(conn, self.current_user)
        try:
            if mode == 'add':
                sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(placeholders)})"
                execute_query(conn, sql, values, table=table, operation='INSERT')
            else:
                pk_column = {
                    'employees': 'employee_id',
                    'projects': 'project_id',
                    'tasks': 'task_id',
                    'assignments': 'assignment_id'
                }.get(table)
                if not pk_column:
                    raise ValueError("Неизвестный первичный ключ")
                pk_value = initial_data[pk_column]
                set_clause = ', '.join([f"{col} = ?" for col in cols])
                sql = f"UPDATE {table} SET {set_clause} WHERE {pk_column} = ?"
                values.append(pk_value)
                execute_query(conn, sql, values, table=table, operation='UPDATE')
            
            conn.commit()
            messagebox.showinfo("Успех", "Данные сохранены")
            dialog.destroy()
            self.refresh_table_view()
        except (sqlite3.Error, PermissionError) as e:
            messagebox.showerror("Ошибка", str(e))
        finally:
            conn.close()
    
    def setup_audit_tab(self):
        """Просмотр логов аудита."""
        # Верхняя панель
        control_frame = tk.Frame(self.tab_audit, bg='#e8e8e8', height=50, relief=tk.GROOVE, bd=1)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        control_frame.pack_propagate(False)
        
        # Выбор таблицы аудита
        tk.Label(control_frame, text="Журнал:", bg='#e8e8e8', 
                font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=15, pady=10)
        
        self.audit_table_var = tk.StringVar(value='audit_log')
        audit_combo = ttk.Combobox(control_frame, textvariable=self.audit_table_var, 
                                   state='readonly', width=20)
        audit_combo['values'] = ('audit_log', 'task_status_history')
        audit_combo.pack(side=tk.LEFT, padx=5)
        audit_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_audit_view())
        
        tk.Button(control_frame, text="🔄 Обновить", 
                 bg='#607d8b', fg='white',
                 font=('Arial', 9), padx=15,
                 command=self.refresh_audit_view).pack(side=tk.RIGHT, padx=15)
        
        # Таблица аудита
        table_frame = tk.Frame(self.tab_audit, bg='white', relief=tk.SUNKEN, bd=1)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        
        v_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)
        h_scroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL)
        
        self.audit_tree = ttk.Treeview(table_frame,
                                       yscrollcommand=v_scroll.set,
                                       xscrollcommand=h_scroll.set,
                                       height=15)
        
        v_scroll.config(command=self.audit_tree.yview)
        h_scroll.config(command=self.audit_tree.xview)
        
        self.audit_tree.grid(row=0, column=0, sticky='nsew')
        v_scroll.grid(row=0, column=1, sticky='ns')
        h_scroll.grid(row=1, column=0, sticky='ew')
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Нижняя панель
        bottom_frame = tk.Frame(self.tab_audit, bg='#e0e0e0', height=30, relief=tk.SUNKEN, bd=1)
        bottom_frame.pack(fill=tk.X, padx=10, pady=(0,5))
        bottom_frame.pack_propagate(False)
        
        tk.Label(bottom_frame, text="Последние 200 записей", 
                bg='#e0e0e0', padx=10).pack(side=tk.LEFT)
        
        tk.Button(bottom_frame, text="📥 Экспорт", 
                 bg='#2196F3', fg='white',
                 font=('Arial', 8), padx=10,
                 command=lambda: messagebox.showinfo("Инфо", "Функция экспорта в разработке")).pack(side=tk.RIGHT, padx=10)
        
        self.refresh_audit_view()
    
    def refresh_audit_view(self):
        """Загружает данные из таблицы аудита."""
        table = self.audit_table_var.get()
        self.audit_tree.delete(*self.audit_tree.get_children())
        
        conn = get_connection()
        try:
            cur = conn.execute(f"SELECT * FROM {table} ORDER BY changed_at DESC LIMIT 200")
            rows = cur.fetchall()
            if rows:
                columns = list(rows[0].keys())
                self.audit_tree['columns'] = columns
                self.audit_tree['show'] = 'headings'
                for col in columns:
                    self.audit_tree.heading(col, text=col)
                    self.audit_tree.column(col, width=120)
                for row in rows:
                    values = [row[col] for col in columns]
                    self.audit_tree.insert('', tk.END, values=values)
        except sqlite3.Error as e:
            messagebox.showerror("Ошибка", str(e))
        finally:
            conn.close()
    
    def setup_backup_tab(self):
        """Интерфейс резервного копирования."""
        # Панель управления
        control_frame = tk.Frame(self.tab_backup, bg='#e8e8e8', height=60, relief=tk.GROOVE, bd=1)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        control_frame.pack_propagate(False)
        
        tk.Label(control_frame, text="💾 Резервное копирование", 
                bg='#e8e8e8', font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=15)
        
        tk.Button(control_frame, text="📀 Создать копию", 
                 bg='#4CAF50', fg='white',
                 font=('Arial', 10), padx=15, pady=5,
                 command=self.do_backup).pack(side=tk.RIGHT, padx=15)
        
        # Список копий
        list_frame = tk.Frame(self.tab_backup, bg='#f0f0f0')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(list_frame, text="Доступные резервные копии:", 
                bg='#f0f0f0', font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        # Контейнер для списка
        list_container = tk.Frame(list_frame, bg='white', relief=tk.SUNKEN, bd=1)
        list_container.pack(fill=tk.BOTH, expand=True, pady=5)
        
        scroll = ttk.Scrollbar(list_container, orient=tk.VERTICAL)
        self.backup_listbox = tk.Listbox(list_container, 
                                         yscrollcommand=scroll.set,
                                         font=('Consolas', 10),
                                         selectbackground='#2196F3',
                                         selectforeground='white')
        scroll.config(command=self.backup_listbox.yview)
        
        self.backup_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Кнопки под списком
        btn_frame = tk.Frame(list_frame, bg='#f0f0f0')
        btn_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(btn_frame, text="🔄 Обновить список", 
                 bg='#607d8b', fg='white',
                 font=('Arial', 9), padx=10,
                 command=self.refresh_backup_list).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="♻️ Восстановить из выбранной копии", 
                 bg='#ff9800', fg='white',
                 font=('Arial', 9, 'bold'), padx=15, pady=3,
                 command=self.do_restore).pack(side=tk.RIGHT, padx=5)
        
        self.refresh_backup_list()
    
    def refresh_backup_list(self):
        """Обновляет список бэкапов."""
        self.backup_listbox.delete(0, tk.END)
        backups = list_backups()
        if backups:
            for f in backups:
                # Добавляем информацию о размере файла
                file_path = os.path.join(BACKUP_DIR, f)
                size = os.path.getsize(file_path)
                size_str = f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
                self.backup_listbox.insert(tk.END, f"📁 {f} ({size_str})")
        else:
            self.backup_listbox.insert(tk.END, "Нет резервных копий")
    
    def do_backup(self):
        """Создание бэкапа."""
        try:
            file = backup_database()
            messagebox.showinfo("Успех", f"Резервная копия создана:\n{os.path.basename(file)}")
            self.refresh_backup_list()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
    
    def do_restore(self):
        """Восстановление из выбранной копии."""
        selection = self.backup_listbox.curselection()
        if not selection:
            messagebox.showinfo("Информация", "Выберите резервную копию")
            return
        
        item_text = self.backup_listbox.get(selection[0])
        # Извлекаем имя файла из строки (до первой скобки)
        filename = item_text.split(' (')[0].replace('📁 ', '')
        
        if messagebox.askyesno("Подтверждение", 
                               f"Восстановить базу данных из копии:\n{filename}\n\nТекущие данные будут потеряны!"):
            if restore_database(filename):
                messagebox.showinfo("Успех", "Восстановление выполнено.\nПерезайдите в систему.")
                self.logout()
            else:
                messagebox.showerror("Ошибка", "Не удалось восстановить")
    
    def setup_test_tab(self):
        """Автоматизированное тестирование механизмов безопасности."""
        # Заголовок
        header_frame = tk.Frame(self.tab_test, bg='#2196F3', height=50)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="🧪 Тестирование системы безопасности", 
                bg='#2196F3', fg='white',
                font=('Arial', 14, 'bold')).pack(expand=True)
        
        # Основная область
        main_frame = tk.Frame(self.tab_test, bg='#f0f0f0', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Кнопка запуска тестов
        tk.Button(main_frame, text="▶️ ЗАПУСТИТЬ ПОЛНОЕ ТЕСТИРОВАНИЕ", 
                 bg='#4CAF50', fg='white',
                 font=('Arial', 12, 'bold'),
                 padx=20, pady=10,
                 command=self.run_tests).pack(pady=10)
        
        # Область вывода результатов
        output_frame = tk.Frame(main_frame, bg='#2b2b2b', relief=tk.SUNKEN, bd=2)
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        scroll = ttk.Scrollbar(output_frame, orient=tk.VERTICAL)
        self.test_output = tk.Text(output_frame, wrap=tk.WORD,
                                   yscrollcommand=scroll.set,
                                   font=('Consolas', 10),
                                   bg='#1e1e1e', fg='#d4d4d4',
                                   insertbackground='white')
        scroll.config(command=self.test_output.yview)
        
        self.test_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Начальное сообщение
        self.test_output.insert(tk.END, "Нажмите кнопку для запуска тестирования...\n")
        self.test_output.config(state=tk.DISABLED)
    
    def run_tests(self):
        """Выполняет набор тестов и выводит результат."""
        self.test_output.config(state=tk.NORMAL)
        self.test_output.delete(1.0, tk.END)
        self.test_output.insert(tk.END, "="*70 + "\n")
        self.test_output.insert(tk.END, "ЗАПУСК ТЕСТИРОВАНИЯ СИСТЕМЫ БЕЗОПАСНОСТИ\n")
        self.test_output.insert(tk.END, "="*70 + "\n\n")
        
        original_user = sec.current_user
        
        def log(msg):
            self.test_output.insert(tk.END, msg + "\n")
            self.test_output.see(tk.END)
            self.update()
        
        try:
            sec.set_current_user('alex_admin')
            conn = get_connection()
            set_session_user(conn, 'alex_admin')
            log("[ADMIN] Проверка DELETE...")
            execute_query(conn, "DELETE FROM assignments WHERE assignment_id = 999", 
                         table='assignments', operation='DELETE')
            log("  ✓ DELETE разрешён")
            conn.close()
            
            sec.set_current_user('maria_manager')
            conn = get_connection()
            set_session_user(conn, 'maria_manager')
            log("\n[MANAGER] Проверка DELETE на assignments...")
            execute_query(conn, "DELETE FROM assignments WHERE assignment_id = 1",
                         table='assignments', operation='DELETE')
            conn.rollback()
            log("  ✓ DELETE на assignments разрешён")
            
            log("[MANAGER] Проверка DELETE на projects (ожидается отказ)...")
            try:
                execute_query(conn, "DELETE FROM projects WHERE project_id = 1",
                             table='projects', operation='DELETE')
                log("  ✗ DELETE разрешён (ОШИБКА)")
            except PermissionError as e:
                log(f"  ✓ DELETE запрещён: {e}")
            conn.close()
            
            sec.set_current_user('ivan_employee')
            conn = get_connection()
            set_session_user(conn, 'ivan_employee')
            log("\n[EMPLOYEE] Проверка INSERT на себя...")
            try:
                execute_query(conn, """
                    INSERT INTO assignments (task_id, employee_id, assigned_date, hours_estimated)
                    VALUES (2, 1, date('now'), 5.0)
                """, table='assignments', operation='INSERT')
                conn.rollback()
                log("  ✓ INSERT на себя разрешён")
            except sqlite3.Error as e:
                log(f"  ✗ INSERT запрещён: {e}")
            
            log("[EMPLOYEE] Проверка INSERT на другого сотрудника (ожидается отказ)...")
            try:
                execute_query(conn, """
                    INSERT INTO assignments (task_id, employee_id, assigned_date, hours_estimated)
                    VALUES (3, 2, date('now'), 5.0)
                """, table='assignments', operation='INSERT')
                conn.rollback()
                log("  ✗ INSERT на другого разрешён (ОШИБКА)")
            except sqlite3.DatabaseError as e:
                log(f"  ✓ INSERT запрещён триггером: {e}")
            
            log("[EMPLOYEE] Проверка DELETE (ожидается отказ)...")
            try:
                execute_query(conn, "DELETE FROM assignments WHERE assignment_id = 1",
                             table='assignments', operation='DELETE')
                log("  ✗ DELETE разрешён (ОШИБКА)")
            except PermissionError as e:
                log(f"  ✓ DELETE запрещён: {e}")
            conn.close()
            
            sec.set_current_user('alex_admin')
            conn = get_connection()
            set_session_user(conn, 'alex_admin')
            log("\n[INTEGRITY] Попытка закрыть проект с незавершёнными задачами...")
            try:
                conn.execute("UPDATE projects SET status = 'completed' WHERE project_id = 1")
                conn.commit()
                log("  ✗ Проект закрыт (ОШИБКА)")
            except sqlite3.DatabaseError as e:
                log(f"  ✓ Триггер сработал: {e}")
            conn.close()
            
            sec.set_current_user('alex_admin')
            conn = get_connection()
            set_session_user(conn, 'alex_admin')
            cur = conn.execute("SELECT COUNT(*) FROM audit_log")
            count = cur.fetchone()[0]
            log(f"\n[AUDIT] Записей в audit_log: {count}")
            cur = conn.execute("SELECT COUNT(*) FROM task_status_history")
            count = cur.fetchone()[0]
            log(f"[AUDIT] Записей в task_status_history: {count}")
            conn.close()
            
        except Exception as e:
            log(f"\n!!! Ошибка тестирования: {e}")
        finally:
            if original_user:
                sec.set_current_user(original_user)
            else:
                sec.set_current_user(None)
        
        log("\n" + "="*70)
        log("ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
        
        self.test_output.config(state=tk.DISABLED)
    
    def logout(self):
        """Возврат к окну входа."""
        sec.set_current_user(None)
        self.current_user = None
        self.current_employee_id = None
        self.withdraw()
        LoginWindow(self, self.on_login_success)
    
    def quit_app(self):
        """Завершение приложения."""
        if messagebox.askyesno("Выход", "Завершить работу?"):
            self.quit()
            self.destroy()

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()