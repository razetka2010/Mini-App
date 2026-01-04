// Глобальные переменные
let tg = null;
let currentUser = null;
let currentUserId = null;
let encryptionKey = null;
let currentPasswords = [];
let sessionToken = null;
let isEditMode = false;
let editPasswordId = null;

// Инициализация приложения
async function initApp() {
    try {
        console.log('🚀 Starting app initialization...');

        // Инициализируем Telegram WebApp
        tg = window.Telegram.WebApp;
        tg.expand();
        tg.ready();

        console.log('📱 Telegram WebApp initialized');
        console.log('Init Data:', tg.initData);
        console.log('Platform:', tg.platform);
        console.log('Version:', tg.version);

        // Получаем initData
        const initData = tg.initData;

        // Отправляем на сервер для авторизации
        console.log('🔐 Sending auth request...');
        const response = await fetch('/api/auth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                initData: initData,
                platform: tg.platform,
                version: tg.version
            })
        });

        console.log('📨 Auth response status:', response.status);

        if (!response.ok) {
            throw new Error(`Auth failed: ${response.status}`);
        }

        const data = await response.json();
        console.log('📊 Auth response data:', data);

        if (data.success) {
            currentUser = data.user.telegram;
            currentUserId = data.user.database.id;
            sessionToken = data.session_token;

            // Сохраняем токен в localStorage
            localStorage.setItem('telegram_session', sessionToken);

            // Показываем информацию о пользователе
            document.getElementById('user-name').textContent =
                currentUser.first_name || currentUser.username || 'Пользователь';

            // Устанавливаем фото если есть
            if (currentUser.photo_url) {
                document.getElementById('user-photo').src = currentUser.photo_url;
            } else {
                // Генерируем аватар по умолчанию
                const defaultAvatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(currentUser.first_name || 'U')}&background=2481cc&color=fff&size=40`;
                document.getElementById('user-photo').src = defaultAvatar;
            }

            // Генерируем ключ шифрования
            await generateEncryptionKey();

            // Загружаем пароли
            await loadPasswords();

            // Показываем приложение
            document.getElementById('loader').classList.add('hidden');
            document.getElementById('app').classList.remove('hidden');

            // Добавляем кнопку в Telegram
            tg.MainButton.setText("Мои пароли").show();
            tg.MainButton.onClick(() => {
                tg.showAlert(`У вас ${currentPasswords.length} сохраненных паролей`);
            });

            console.log('✅ App initialized successfully');

        } else {
            throw new Error(data.message || 'Auth failed');
        }

    } catch (error) {
        console.error('❌ Initialization error:', error);

        // Показываем ошибку пользователю
        document.getElementById('loader').innerHTML = `
            <div style="text-align: center; padding: 20px;">
                <h3 style="color: #dc3545;">Ошибка загрузки</h3>
                <p>${error.message || 'Неизвестная ошибка'}</p>
                <div style="margin-top: 20px; color: #666; font-size: 14px;">
                    <p>Проверьте:</p>
                    <p>1. Запущен ли сервер?</p>
                    <p>2. Правильно ли настроена база данных?</p>
                </div>
                <button onclick="location.reload()" style="
                    background: #2481cc;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    margin-top: 20px;
                    cursor: pointer;
                ">Перезагрузить</button>
            </div>
        `;
    }
}

// Генерация ключа шифрования
async function generateEncryptionKey() {
    try {
        if (!currentUser || !currentUser.id) {
            throw new Error('No user ID for key generation');
        }

        // Используем Telegram ID как основу для ключа
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(currentUser.id.toString()),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        encryptionKey = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: new TextEncoder().encode("telegram-password-manager"),
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );

        console.log('🔑 Encryption key generated');
    } catch (error) {
        console.error('Key generation error:', error);
        throw error;
    }
}

// Шифрование пароля
async function encryptPassword(password) {
    try {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(password);

        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            encryptionKey,
            encoded
        );

        // Преобразуем в base64
        const encryptedArray = new Uint8Array(encrypted);
        let encryptedString = '';
        for (let i = 0; i < encryptedArray.length; i++) {
            encryptedString += String.fromCharCode(encryptedArray[i]);
        }

        let ivString = '';
        for (let i = 0; i < iv.length; i++) {
            ivString += String.fromCharCode(iv[i]);
        }

        return {
            encrypted: btoa(encryptedString),
            iv: btoa(ivString)
        };
    } catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}

// Дешифрование пароля
async function decryptPassword(encryptedData, iv) {
    try {
        const encryptedBinary = atob(encryptedData);
        const encryptedArray = new Uint8Array(encryptedBinary.length);
        for (let i = 0; i < encryptedBinary.length; i++) {
            encryptedArray[i] = encryptedBinary.charCodeAt(i);
        }

        const ivBinary = atob(iv);
        const ivArray = new Uint8Array(ivBinary.length);
        for (let i = 0; i < ivBinary.length; i++) {
            ivArray[i] = ivBinary.charCodeAt(i);
        }

        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivArray
            },
            encryptionKey,
            encryptedArray
        );

        return new TextDecoder().decode(decrypted);
    } catch (error) {
        console.error('Decryption error:', error);
        return '***Ошибка***';
    }
}

// Аутентифицированный запрос
async function makeAuthenticatedRequest(url, options = {}) {
    if (!sessionToken) {
        console.error('No session token');
        return null;
    }

    const defaultHeaders = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + sessionToken
    };

    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                ...defaultHeaders,
                ...options.headers
            }
        });

        if (response.status === 401) {
            tg.showAlert('Сессия истекла. Перезагрузите приложение.');
            return null;
        }

        return response;
    } catch (error) {
        console.error('Request error:', error);
        tg.showAlert('Ошибка подключения');
        return null;
    }
}

// Загрузка паролей
async function loadPasswords() {
    try {
        console.log('📥 Loading passwords...');
        const response = await makeAuthenticatedRequest('/api/passwords');
        if (!response) return;

        const data = await response.json();
        console.log('📦 Passwords loaded:', data);

        if (data.success) {
            currentPasswords = data.passwords || [];
            renderPasswords();
            updateStats();
        }
    } catch (error) {
        console.error('Error loading passwords:', error);
    }
}

// Отображение паролей
function renderPasswords() {
    const list = document.getElementById('passwords-list');
    list.innerHTML = '';

    if (currentPasswords.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-lock-open"></i>
                <p>Пока нет сохраненных паролей</p>
                <p style="font-size: 14px; color: #888;">Добавьте ваш первый пароль выше</p>
            </div>
        `;
        return;
    }

    for (const item of currentPasswords) {
        const div = document.createElement('div');
        div.className = 'password-item';
        div.dataset.id = item.id;

        div.innerHTML = `
            <div class="service-info">
                <div class="service-name">${escapeHtml(item.service_name)}</div>
                <div class="login">${escapeHtml(item.login)}</div>
            </div>
            <div class="password-actions">
                <button class="action-btn" title="Посмотреть пароль">
                    <i class="fas fa-eye"></i>
                </button>
                <button class="action-btn" title="Редактировать">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="action-btn" title="Удалить">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;

        // Назначаем обработчики
        const viewBtn = div.querySelector('.action-btn:nth-child(1)');
        const editBtn = div.querySelector('.action-btn:nth-child(2)');
        const deleteBtn = div.querySelector('.action-btn:nth-child(3)');

        viewBtn.onclick = () => showPassword(item.id);
        editBtn.onclick = () => editPassword(item.id);
        deleteBtn.onclick = () => confirmDelete(item.id);

        list.appendChild(div);
    }
}

// Показать пароль
async function showPassword(id) {
    const password = currentPasswords.find(p => p.id == id);
    if (!password) return;

    try {
        const decryptedPassword = await decryptPassword(
            password.encrypted_password,
            password.iv
        );

        document.getElementById('modal-service').textContent = password.service_name;
        document.getElementById('modal-login').value = password.login;
        document.getElementById('modal-password').value = decryptedPassword;
        document.getElementById('password-modal').dataset.id = id;

        // Устанавливаем поля только для чтения
        document.getElementById('modal-login').readOnly = true;
        document.getElementById('modal-password').readOnly = true;

        // Скрываем кнопку редактирования в режиме просмотра
        document.getElementById('modal-edit-btn').classList.remove('hidden');
        document.getElementById('modal-save-btn').classList.add('hidden');
        document.getElementById('modal-cancel-btn').classList.add('hidden');

        document.getElementById('password-modal').classList.remove('hidden');

    } catch (error) {
        console.error('Error showing password:', error);
        tg.showAlert('Ошибка при загрузке пароля');
    }
}

// Редактировать пароль
async function editPassword(id) {
    const password = currentPasswords.find(p => p.id == id);
    if (!password) return;

    try {
        const decryptedPassword = await decryptPassword(
            password.encrypted_password,
            password.iv
        );

        document.getElementById('modal-service').textContent = 'Редактирование пароля: ' + password.service_name;
        document.getElementById('modal-login').value = password.login;
        document.getElementById('modal-password').value = decryptedPassword;
        document.getElementById('password-modal').dataset.id = id;

        // Разрешаем редактирование полей
        document.getElementById('modal-login').readOnly = false;
        document.getElementById('modal-password').readOnly = false;

        // Показываем кнопки редактирования
        document.getElementById('modal-edit-btn').classList.add('hidden');
        document.getElementById('modal-save-btn').classList.remove('hidden');
        document.getElementById('modal-cancel-btn').classList.remove('hidden');

        isEditMode = true;
        editPasswordId = id;

        document.getElementById('password-modal').classList.remove('hidden');

    } catch (error) {
        console.error('Error editing password:', error);
        tg.showAlert('Ошибка при загрузке пароля');
    }
}

// Сохранить изменения пароля
async function savePassword() {
    const id = document.getElementById('password-modal').dataset.id;
    const newLogin = document.getElementById('modal-login').value.trim();
    const newPassword = document.getElementById('modal-password').value.trim();

    console.log('Saving password:', { id, newLogin, newPassword });

    if (!newLogin || !newPassword) {
        tg.showAlert('Логин и пароль не могут быть пустыми!');
        return;
    }

    try {
        const encrypted = await encryptPassword(newPassword);
        console.log('Encrypted password:', encrypted);

        const response = await makeAuthenticatedRequest(`/api/passwords/${id}`, {
            method: 'PUT',
            body: JSON.stringify({
                login: newLogin,
                encrypted_password: encrypted.encrypted,
                iv: encrypted.iv
            })
        });

        console.log('Save response:', response);

        if (!response) {
            console.error('No response from server');
            return;
        }

        const data = await response.json();
        console.log('Save response data:', data);

        if (data.success) {
            tg.showAlert('Пароль обновлен!');
            closeModal();
            await loadPasswords();

            // Вибрация
            if (tg.HapticFeedback) {
                tg.HapticFeedback.impactOccurred('medium');
            }
        } else {
            console.error('Server error:', data);
            tg.showAlert(data.message || 'Ошибка при обновлении пароля');
        }

    } catch (error) {
        console.error('Error saving password:', error);
        tg.showAlert('Ошибка при сохранении: ' + error.message);
    }
}

// Отменить редактирование
function cancelEdit() {
    const id = document.getElementById('password-modal').dataset.id;
    showPassword(id); // Возвращаемся в режим просмотра
}

// Добавить пароль
async function addPassword() {
    const serviceName = document.getElementById('service-name').value.trim();
    const login = document.getElementById('login').value.trim();
    const password = document.getElementById('password').value.trim();

    if (!serviceName || !login || !password) {
        tg.showAlert('Заполните все поля!');
        return;
    }

    try {
        const encrypted = await encryptPassword(password);

        const response = await makeAuthenticatedRequest('/api/passwords', {
            method: 'POST',
            body: JSON.stringify({
                service_name: serviceName,
                login: login,
                encrypted_password: encrypted.encrypted,
                iv: encrypted.iv
            })
        });

        if (!response) return;

        const data = await response.json();

        if (data.success) {
            // Очищаем форму
            document.getElementById('service-name').value = '';
            document.getElementById('login').value = '';
            document.getElementById('password').value = '';
            document.getElementById('password').type = 'password';
            document.querySelector('#toggle-password i').className = 'fas fa-eye';

            // Обновляем список
            await loadPasswords();

            tg.showAlert('Пароль сохранен!');

            // Вибрация
            if (tg.HapticFeedback) {
                tg.HapticFeedback.impactOccurred('soft');
            }
        }

    } catch (error) {
        console.error('Error adding password:', error);
        tg.showAlert('Ошибка при сохранении');
    }
}

// Генерация пароля
function generatePassword() {
    const length = 12;
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    let password = "";

    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }

    document.getElementById('password').value = password;
    document.getElementById('password').type = 'text';
    document.querySelector('#toggle-password i').className = 'fas fa-eye-slash';
}

// Удалить пароль
async function deletePassword() {
    const id = document.getElementById('password-modal').dataset.id;

    try {
        const response = await makeAuthenticatedRequest(`/api/passwords/${id}`, {
            method: 'DELETE',
            body: JSON.stringify({ id: id })
        });

        if (!response) return;

        const data = await response.json();

        if (data.success) {
            closeModal();
            await loadPasswords();
            tg.showAlert('Пароль удален');
        }

    } catch (error) {
        console.error('Error deleting password:', error);
        tg.showAlert('Ошибка при удалении');
    }
}

// Подтверждение удаления
function confirmDelete(id) {
    if (confirm('Удалить этот пароль?')) {
        makeAuthenticatedRequest(`/api/passwords/${id}`, {
            method: 'DELETE',
            body: JSON.stringify({ id: id })
        })
            .then(response => response && response.json())
            .then(data => {
                if (data && data.success) {
                    loadPasswords();
                    tg.showAlert('Пароль удален');
                }
            });
    }
}

// Закрыть модальное окно
function closeModal() {
    document.getElementById('password-modal').classList.add('hidden');
    document.getElementById('modal-password').type = 'password';
    document.querySelector('.modal-field .toggle-password i').className = 'fas fa-eye';
    document.getElementById('modal-login').readOnly = true;
    document.getElementById('modal-password').readOnly = true;
    isEditMode = false;
    editPasswordId = null;
}

// Переключить видимость пароля в модальном окне
function toggleModalPassword() {
    const input = document.getElementById('modal-password');
    const icon = event.target.closest('button').querySelector('i');

    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

// Копировать в буфер обмена
async function copyToClipboard(inputId) {
    const input = document.getElementById(inputId);
    input.select();

    try {
        await navigator.clipboard.writeText(input.value);
        tg.showAlert('Скопировано!');

        if (tg.HapticFeedback) {
            tg.HapticFeedback.impactOccurred('light');
        }
    } catch (err) {
        input.select();
        document.execCommand('copy');
        tg.showAlert('Скопировано!');
    }
}

// Обновить статистику
function updateStats() {
    document.getElementById('total-passwords').textContent = currentPasswords.length;

    if (currentPasswords.length > 0) {
        const last = currentPasswords[0];
        document.getElementById('last-added').textContent =
            last.service_name.length > 15 ?
                last.service_name.substring(0, 15) + '...' :
                last.service_name;
    } else {
        document.getElementById('last-added').textContent = '-';
    }
}

// Экранирование HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Инициализация обработчиков
function initEventHandlers() {
    // Переключение видимости пароля
    document.getElementById('toggle-password').addEventListener('click', function() {
        const input = document.getElementById('password');
        const icon = this.querySelector('i');

        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'fas fa-eye';
        }
    });

    // Добавление по Enter
    document.getElementById('password').addEventListener('keyup', function(e) {
        if (e.key === 'Enter') {
            addPassword();
        }
    });

    // Закрытие модального окна
    document.getElementById('password-modal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeModal();
        }
    });

    // Закрытие по ESC
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeModal();
        }
    });
}

// Глобальные функции
window.addPassword = addPassword;
window.generatePassword = generatePassword;
window.showPassword = showPassword;
window.editPassword = editPassword;
window.savePassword = savePassword;
window.cancelEdit = cancelEdit;
window.deletePassword = deletePassword;
window.confirmDelete = confirmDelete;
window.closeModal = closeModal;
window.toggleModalPassword = toggleModalPassword;
window.copyToClipboard = copyToClipboard;
window.filterPasswords = function() {
    const search = document.getElementById('search').value.toLowerCase();
    const items = document.querySelectorAll('.password-item');

    items.forEach(item => {
        const serviceName = item.querySelector('.service-name').textContent.toLowerCase();
        const login = item.querySelector('.login').textContent.toLowerCase();

        if (serviceName.includes(search) || login.includes(search)) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });
};

// Запуск приложения
document.addEventListener('DOMContentLoaded', function() {
    console.log('📄 DOM loaded');
    initEventHandlers();
    initApp();
});