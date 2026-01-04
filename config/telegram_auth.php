<?php
class TelegramAuth {

    /**
     * Проверяет подлинность данных от Telegram
     * @param string $initData - строка initData от Telegram WebApp
     * @param string $botToken - токен вашего бота
     * @return bool
     */
    public static function validate($initData, $botToken) {
        // Разбиваем строку на параметры
        parse_str($initData, $data);

        // Извлекаем хеш и удаляем его из данных
        if (!isset($data['hash'])) {
            return false;
        }
        $hash = $data['hash'];
        unset($data['hash']);

        // Сортируем параметры по алфавиту
        ksort($data);

        // Формируем строку данных
        $dataCheckArr = [];
        foreach ($data as $key => $value) {
            $dataCheckArr[] = $key . '=' . $value;
        }
        $dataCheckString = implode("\n", $dataCheckArr);

        // Вычисляем секретный ключ
        $secretKey = hash_hmac('sha256', $botToken, "WebAppData", true);

        // Вычисляем ожидаемый хеш
        $expectedHash = bin2hex(
            hash_hmac('sha256', $dataCheckString, $secretKey, true)
        );

        // Сравниваем хеши (тайминг3-safe сравнение)
        return hash_equals($expectedHash, $hash);
    }

    /**
     * Извлекает данные пользователя из initData
     * @param string $initData
     * @return array|null
     */
    public static function getUserData($initData) {
        parse_str($initData, $data);

        if (isset($data['user'])) {
            $userData = json_decode($data['user'], true);

            // Проверяем обязательные поля
            if (isset($userData['id']) && isset($userData['first_name'])) {
                return [
                    'id' => (int)$userData['id'],
                    'first_name' => $userData['first_name'],
                    'last_name' => $userData['last_name'] ?? null,
                    'username' => $userData['username'] ?? null,
                    'language_code' => $userData['language_code'] ?? null,
                    'is_premium' => $userData['is_premium'] ?? false,
                    'photo_url' => $userData['photo_url'] ?? null
                ];
            }
        }

        return null;
    }

    /**
     * Проверяет, не устарели ли данные
     * @param string $initData
     * @param int $maxAgeSeconds - максимальный возраст данных в секундах (по умолчанию 1 день)
     * @return bool
     */
    public static function isFresh($initData, $maxAgeSeconds = 86400) {
        parse_str($initData, $data);

        if (!isset($data['auth_date'])) {
            return false;
        }

        $authTimestamp = (int)$data['auth_date'];
        $currentTimestamp = time();

        return ($currentTimestamp - $authTimestamp) <= $maxAgeSeconds;
    }
}
?>