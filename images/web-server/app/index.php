<?php
// Deliberately vulnerable web application for demonstration purposes

// Vulnerable to SQL Injection
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    echo "You requested item ID: " . $id;
    
    // Simulating SQL query vulnerable to injection
    echo "<br>SQL query: SELECT * FROM products WHERE id = " . $id;
}

// Vulnerable login form
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    echo "<br>Login attempt with username: " . $username;
    
    // Simulating authentication (insecure)
    if ($username == "admin" && $password == "admin123") {
        echo "<br>Login successful!";
    } else {
        echo "<br>Login failed!";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Web Application</title>
</head>
<body>
    <h1>Vulnerable Web Application</h1>
    
    <h2>Search Product (SQL Injectable)</h2>
    <form method="GET">
        Product ID: <input type="text" name="id">
        <input type="submit" value="Search">
    </form>
    
    <h2>Login Form</h2>
    <form method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>