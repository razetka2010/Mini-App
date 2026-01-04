<?php
require_once '../config/database.php';

$database = new Database();
$db = $database->getConnection();

$method = $_SERVER['REQUEST_METHOD'];

switch ($method) {
    case 'GET':
        // Получить все пароли пользователя
        $user_id = $_GET['user_id'] ?? 0;

        $query = "SELECT id, service_name, login, encrypted_password, iv 
                  FROM passwords WHERE user_id = :user_id 
                  ORDER BY created_at DESC";

        $stmt = $db->prepare($query);
        $stmt->bindParam(':user_id', $user_id);
        $stmt->execute();

        $passwords = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode([
            'success' => true,
            'passwords' => $passwords
        ]);
        break;

    case 'POST':
        // Добавить новый пароль
        $data = json_decode(file_get_contents('php://input'), true);

        $query = "INSERT INTO passwords (user_id, service_name, login, encrypted_password, iv) 
                  VALUES (:user_id, :service_name, :login, :encrypted_password, :iv)";

        $stmt = $db->prepare($query);
        $stmt->bindParam(':user_id', $data['user_id']);
        $stmt->bindParam(':service_name', $data['service_name']);
        $stmt->bindParam(':login', $data['login']);
        $stmt->bindParam(':encrypted_password', $data['encrypted_password']);
        $stmt->bindParam(':iv', $data['iv']);

        if ($stmt->execute()) {
            echo json_encode(['success' => true, 'id' => $db->lastInsertId()]);
        } else {
            echo json_encode(['success' => false]);
        }
        break;

    case 'DELETE':
        // Удалить пароль
        parse_str(file_get_contents('php://input'), $data);
        $id = $data['id'] ?? 0;
        $user_id = $data['user_id'] ?? 0;

        $query = "DELETE FROM passwords WHERE id = :id AND user_id = :user_id";

        $stmt = $db->prepare($query);
        $stmt->bindParam(':id', $id);
        $stmt->bindParam(':user_id', $user_id);

        echo json_encode(['success' => $stmt->execute()]);
        break;
}
?>
