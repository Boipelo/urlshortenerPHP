<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, DELETE, PUT');
header("Access-Control-Allow-Headers: X-Requested-With");
require 'vendor/autoload.php'; // Include Composer autoload

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

// Database initialization
$db_host = '127.0.0.1';
$db_user = 'root';
$db_password = 'root';
$db_db = 'urlshortener';
$db_port = 3306;
$key = 'mY$uPeR$eCRetKEY';

$mysqli = new mysqli(
    $db_host,
    $db_user,
    $db_password,
    $db_db,
    $db_port
);

if ($mysqli->connect_error) {
    exit();
}

// Function to generate JWT token
function generateJWT($id)
{
    global $key;
    $payload = [
        'iss' => 'http://example.com', // Issuer
        'iat' => time(), // Issued at
        'exp' => time() + (60 * 60), // Expiration time (1 hour)
        'sub' => $id // Subject (user ID)
    ];

    return JWT::encode($payload, $key, 'HS256');
}

// Function to verify JWT token
function verifyJWT($token)
{
    global $key;
    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        return (array) $decoded;
    } catch (Exception $e) {
        return null;
    }
}

// Function to register a new user
function register($email, $password)
{
    global $mysqli;

    // Check if the email already exists
    $stmt = $mysqli->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        return json_encode(["status" => 400, "message" => "User already exists."]);
    }

    // Insert new user
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    $stmt = $mysqli->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $email, $hashed_password);

    if ($stmt->execute()) {
        $id = $stmt->insert_id; // Get the user ID
        $token = generateJWT($id); // Generate JWT token
        return json_encode([
            "status" => 200,
            "message" => "User registered successfully.",
            "profile" => $id,
            "token" => $token
        ]);
    } else {
        return json_encode(["status" => 500, "message" => "Server error."]);
    }
}

// Function to log in a user
function login($email, $password)
{
    global $mysqli;

    // Check if the email exists
    $stmt = $mysqli->prepare("SELECT id, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($id, $hashed_password);
        $stmt->fetch();

        // Verify password
        if (password_verify($password, $hashed_password)) {
            $token = generateJWT($id); // Generate JWT token
            return json_encode([
                "status" => 200,
                "message" => "Login successful.",
                "profile" => $id,
                "token" => $token
            ]);
        } else {
            return json_encode(["status" => 401, "message" => "Invalid email or password."]);
        }
    } else {
        return json_encode(["status" => 401, "message" => "Invalid email or password."]);
    }
}

function getAllLinks($userID)
{
    global $mysqli;

    $stmt = $mysqli->prepare("SELECT * FROM links WHERE userID = ?");
    $stmt->bind_param("i", $userID);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $urls = array();
        while ($row = $result->fetch_assoc()) {
            $urls[] = $row;
        }
        // return json_encode($urls);
        return json_encode(["status" => 200, "message" => "Retrieved all links.", "data" => $urls]);
    } else {
        return array();
    }
}

function generateShortCode($length = 8)
{
    return substr(str_shuffle("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, $length);
}

function shortenUrl($originalUrl, $userID)
{
    global $mysqli;
    $shortUrl = generateShortCode();

    // Check if the short code already exists
    $stmt = $mysqli->prepare("SELECT * FROM links WHERE shortUrl = ?");
    $stmt->bind_param("s", $shortUrl);
    $stmt->execute();
    $result = $stmt->get_result();

    while ($result->num_rows > 0) {
        $shortUrl = generateShortCode();
        $stmt->bind_param("s", $shortUrl);
        $stmt->execute();
        $result = $stmt->get_result();
    }

    // Insert the URL and short code into the database
    $stmt = $mysqli->prepare("INSERT INTO links (originalUrl, shortUrl, userID) VALUES (?, ?, ?)");
    $stmt->bind_param("ssi", $originalUrl, $shortUrl, $userID);
    $stmt->execute();

    return json_encode(["status" => 200, "message" => "URL shortened"]);
}

function redirect($shortUrl)
{

    global $mysqli;

    // Fetch the original URL from the database
    $stmt = $mysqli->prepare("SELECT originalUrl FROM links WHERE shortUrl = ?");
    $stmt->bind_param("s", $shortUrl);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        header("Location: " . $row['originalUrl']);
        exit();
    } else {
        echo "URL not found.";
    }
}

function updateUrl($shortUrl, $newUrl)
{
    global $mysqli;
    // Update the original URL in the database
    $stmt = $mysqli->prepare("UPDATE links SET originalUrl = ? WHERE shortUrl = ?");
    $stmt->bind_param("ss", $newUrl, $shortUrl);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        return json_encode(["status" => 200, "message" => "URL updated successfully."]);
    } else {
        return json_encode(["status" => 400, "message" => "Short URL not found or URL is the same."]);
    }
    $stmt->close();
}

function deleteUrl($shortUrl)
{
    global $mysqli;

    // Delete the URL from the database
    $stmt = $mysqli->prepare("DELETE FROM links WHERE shortUrl = ?");
    $stmt->bind_param("s", $shortUrl);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        return json_encode(["status" => 200, "message" => "URL deleted successfully."]);
    } else {
        return json_encode(["status" => 404, "message" => "URL updated successfully."]);
    }

    $stmt->close();
}

// Function for token verification
// function protectedEndpoint()
// {
//     $headers = apache_request_headers();
//     if (!isset($headers['Authorization'])) {
//         return json_encode(["status" => "error", "message" => "No token provided"]);
//     }

//     $token = str_replace('Bearer ', '', $headers['Authorization']);
//     $decoded = verifyJWT($token);

//     if ($decoded) {
//         return true;
//     } else {
//         return false;
//     }
// }

// Handle incoming requests - parse user input from either URL parameter or req body.
parse_str(file_get_contents("php://input"), $body);
$jsonData = file_get_contents('php://input');
$data = json_decode($jsonData, true);
$action = $_GET['action'] ?? $data['action'] ?? null;
$email = $_GET['email'] ?? $data['email'] ?? null;
$password = $_GET['password'] ?? $data['password'] ?? null;
$originalUrl = $_GET['originalUrl'] ?? $data['originalUrl'] ?? null;
$userID = $_GET['userID'] ?? $data['userID'] ?? null;
$shortUrl = $_GET['shortUrl'] ?? $data['shortUrl'] ?? null;
$newUrl = $_GET['newUrl'] ?? $data['newUrl'] ?? null;
$headers = apache_request_headers();
// echo json_encode($body);

switch ($action) {
    case 'register':
        echo register($email, $password);
        break;
    case 'login':
        echo login($email, $password);
        break;
    case 'shorten':
        echo shortenUrl($originalUrl, $userID);
        break;
    case 'all':
        echo getAllLinks($userID);
        break;
    case 'redirect':
        echo redirect($shortUrl);
        break;
    case 'update':
        echo updateUrl($shortUrl, $newUrl);
        break;
    case 'delete':
        echo deleteUrl($shortUrl);
        break;
    default:
        echo json_encode(["status" => 400, "message" => "Invalid request type."]);
        break;
}

$mysqli->close();
