<?php
session_start();
require_once 'config.php';

setCorsHeaders();

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = explode('/', $uri);

// Get the endpoint and action
$endpoint = $uri[count($uri) - 2] ?? '';
$action = $uri[count($uri) - 1] ?? '';

// Parse JSON input for POST/PUT requests
$input = [];
if (in_array($method, ['POST', 'PUT'])) {
    $json = file_get_contents('php://input');
    $input = json_decode($json, true) ?? [];
}

try {
    switch ($endpoint) {
        case 'auth':
            handleAuth($action, $input);
            break;
        case 'tickets':
            handleTickets($action, $input);
            break;
        case 'users':
            handleUsers($action, $input);
            break;
        case 'dashboard':
            handleDashboard($action, $input);
            break;
        default:
            errorResponse('Invalid endpoint', 404);
    }
} catch (Exception $e) {
    error_log("API Error: " . $e->getMessage());
    errorResponse('Server error occurred', 500);
}

// Authentication handlers
function handleAuth($action, $input) {
    switch ($action) {
        case 'login':
            login($input);
            break;
        case 'register':
            register($input);
            break;
        case 'logout':
            logout();
            break;
        case 'session':
            getSession();
            break;
        default:
            errorResponse('Invalid auth action');
    }
}

function login($input) {
    $email = $input['email'] ?? '';
    $password = $input['password'] ?? '';
    $role = $input['role'] ?? '';
    
    if (empty($email) || empty($password) || empty($role)) {
        errorResponse('Email, password, and role are required');
    }
    
    $pdo = getDbConnection();
    $stmt = $pdo->prepare("SELECT id, name, email, password_hash, role, approved FROM users WHERE email = ? AND role = ?");
    $stmt->execute([$email, $role]);
    $user = $stmt->fetch();
    
    if (!$user || !password_verify($password, $user['password_hash'])) {
        errorResponse('Invalid credentials');
    }
    
    if ($user['role'] === 'technician' && !$user['approved']) {
        errorResponse('Your technician account is pending admin approval');
    }
    
    // Store user session
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_role'] = $user['role'];
    $_SESSION['user_name'] = $user['name'];
    $_SESSION['user_email'] = $user['email'];
    
    successResponse([
        'user' => [
            'id' => $user['id'],
            'name' => $user['name'],
            'email' => $user['email'],
            'role' => $user['role']
        ]
    ]);
}

function register($input) {
    $name = $input['name'] ?? '';
    $email = $input['email'] ?? '';
    $password = $input['password'] ?? '';
    $phone = $input['phone'] ?? '';
    $role = $input['role'] ?? '';
    
    if (empty($name) || empty($email) || empty($password) || empty($phone) || empty($role)) {
        errorResponse('All fields are required');
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        errorResponse('Invalid email format');
    }
    
    if (strlen($password) < 6) {
        errorResponse('Password must be at least 6 characters');
    }
    
    $pdo = getDbConnection();
    
    // Check if email already exists
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        errorResponse('Email already exists');
    }
    
    // Hash password and insert user
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    $approved = ($role === 'customer') ? 1 : 0; // Auto-approve customers
    
    $stmt = $pdo->prepare("INSERT INTO users (name, email, password_hash, phone, role, approved) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->execute([$name, $email, $passwordHash, $phone, $role, $approved]);
    
    $message = $role === 'technician' 
        ? 'Registration successful! Your account is pending admin approval.'
        : 'Registration successful! You can now login.';
    
    successResponse(['message' => $message]);
}

function logout() {
    session_destroy();
    successResponse(['message' => 'Logged out successfully']);
}

function getSession() {
    if (isset($_SESSION['user_id'])) {
        successResponse([
            'user' => [
                'id' => $_SESSION['user_id'],
                'name' => $_SESSION['user_name'],
                'email' => $_SESSION['user_email'],
                'role' => $_SESSION['user_role']
            ]
        ]);
    } else {
        errorResponse('No active session', 401);
    }
}

// Ticket handlers
function handleTickets($action, $input) {
    requireAuth();
    
    switch ($action) {
        case 'create':
            createTicket($input);
            break;
        case 'list':
            listTickets();
            break;
        case 'update':
            updateTicket($input);
            break;
        case 'assign':
            assignTicket($input);
            break;
        case 'notes':
            addTicketNotes($input);
            break;
        default:
            errorResponse('Invalid ticket action');
    }
}

function createTicket($input) {
    $deviceType = $input['deviceType'] ?? '';
    $deviceModel = $input['deviceModel'] ?? '';
    $issueDescription = $input['issueDescription'] ?? '';
    
    if (empty($deviceType) || empty($deviceModel) || empty($issueDescription)) {
        errorResponse('All fields are required');
    }
    
    $pdo = getDbConnection();
    $stmt = $pdo->prepare("CALL CreateTicket(?, ?, ?, ?)");
    $stmt->execute([$_SESSION['user_id'], $deviceType, $deviceModel, $issueDescription]);
    
    $result = $stmt->fetch();
    successResponse(['ticketId' => $result['ticket_id'], 'message' => 'Ticket created successfully']);
}

function listTickets() {
    $pdo = getDbConnection();
    $role = $_SESSION['user_role'];
    $userId = $_SESSION['user_id'];
    
    // Remove this debug line!
    // echo 'hello';
    
    try {
        switch ($role) {
            case 'customer':
                $stmt = $pdo->prepare("SELECT * FROM ticket_details WHERE customer_id = ? ORDER BY created_at DESC");
                $stmt->execute([$userId]);
                break;
            case 'technician':
                $stmt = $pdo->prepare("SELECT * FROM ticket_details WHERE technician_id = ? ORDER BY created_at DESC");
                $stmt->execute([$userId]);
                break;
            case 'admin':
                $stmt = $pdo->prepare("SELECT * FROM ticket_details ORDER BY created_at DESC");
                $stmt->execute();
                break;
            default:
                errorResponse('Invalid role', 403);
                return;
        }
        
        $tickets = $stmt->fetchAll(PDO::FETCH_ASSOC);
        successResponse($tickets);
        
    } catch (PDOException $e) {
        error_log("Database error in listTickets: " . $e->getMessage());
        errorResponse('Failed to retrieve tickets', 500);
    }
}

function updateTicket($input) {
    $ticketId = $input['ticketId'] ?? '';
    $status = $input['status'] ?? '';
    $notes = $input['notes'] ?? null;
    
    if (empty($ticketId) || empty($status)) {
        errorResponse('Ticket ID and status are required');
    }
    
    $pdo = getDbConnection();
    $stmt = $pdo->prepare("CALL UpdateTicketStatus(?, ?, ?, ?)");
    $stmt->execute([$ticketId, $status, $_SESSION['user_id'], $notes]);
    
    successResponse(['message' => 'Ticket updated successfully']);
}

function assignTicket($input) {
    requireRole('admin');
    
    $ticketId = $input['ticketId'] ?? '';
    $technicianId = $input['technicianId'] ?? '';
    
    if (empty($ticketId) || empty($technicianId)) {
        errorResponse('Ticket ID and technician ID are required');
    }
    
    $pdo = getDbConnection();
    $stmt = $pdo->prepare("CALL AssignTicket(?, ?, ?)");
    $stmt->execute([$ticketId, $technicianId, $_SESSION['user_id']]);
    
    $result = $stmt->fetch();
    if ($result['result'] === 'SUCCESS') {
        successResponse(['message' => 'Ticket assigned successfully']);
    } else {
        errorResponse('Failed to assign ticket');
    }
}

function addTicketNotes($input) {
    $ticketId = $input['ticketId'] ?? '';
    $notes = $input['notes'] ?? '';
    
    if (empty($ticketId) || empty($notes)) {
        errorResponse('Ticket ID and notes are required');
    }
    
    $pdo = getDbConnection();
    $stmt = $pdo->prepare("UPDATE tickets SET notes = ? WHERE id = ?");
    $stmt->execute([$notes, $ticketId]);
    
    successResponse(['message' => 'Notes added successfully']);
}

// User handlers
function handleUsers($action, $input) {
    requireAuth();
    
    switch ($action) {
        case 'technicians':
            getTechnicians();
            break;
        case 'pending':
            getPendingTechnicians();
            break;
        case 'approve':
            approveTechnician($input);
            break;
        case 'reject':
            rejectTechnician($input);
            break;
        default:
            errorResponse('Invalid user action');
    }
}

function getTechnicians() {
    $pdo = getDbConnection();
    $stmt = $pdo->prepare("SELECT id, name, email, phone FROM users WHERE role = 'technician' AND approved = 1");
    $stmt->execute();
    
    $technicians = $stmt->fetchAll();
    successResponse($technicians);
}

function getPendingTechnicians() {
    requireRole('admin');
    
    $pdo = getDbConnection();
    $stmt = $pdo->prepare("SELECT id, name, email, phone, created_at FROM users WHERE role = 'technician' AND approved = 0");
    $stmt->execute();
    
    $pendingTechs = $stmt->fetchAll();
    successResponse($pendingTechs);
}

function approveTechnician($input) {
    requireRole('admin');
    
    $technicianId = $input['technicianId'] ?? '';
    
    if (empty($technicianId)) {
        errorResponse('Technician ID is required');
    }
    
    $pdo = getDbConnection();
    $stmt = $pdo->prepare("CALL ApproveTechnician(?, ?)");
    $stmt->execute([$technicianId, $_SESSION['user_id']]);
    
    successResponse(['message' => 'Technician approved successfully']);
}

function rejectTechnician($input) {
    requireRole('admin');
    
    $technicianId = $input['technicianId'] ?? '';
    
    if (empty($technicianId)) {
        errorResponse('Technician ID is required');
    }
    
    $pdo = getDbConnection();
    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ? AND role = 'technician' AND approved = 0");
    $stmt->execute([$technicianId]);
    
    successResponse(['message' => 'Technician application rejected']);
}

// Dashboard handlers
function handleDashboard($action, $input) {
    requireAuth();
    
    switch ($action) {
        case 'stats':
            getDashboardStats();
            break;
        default:
            errorResponse('Invalid dashboard action');
    }
}

function getDashboardStats() {
    $pdo = getDbConnection();
    $stmt = $pdo->prepare("CALL GetDashboardStats(?, ?)");
    $stmt->execute([$_SESSION['user_id'], $_SESSION['user_role']]);
    
    $stats = $stmt->fetch();
    successResponse($stats);
}

// Helper functions
function requireAuth() {
    if (!isset($_SESSION['user_id'])) {
        errorResponse('Authentication required', 401);
    }
}

function requireRole($role) {
    requireAuth();
    if ($_SESSION['user_role'] !== $role) {
        errorResponse('Insufficient permissions', 403);
    }
}
?>