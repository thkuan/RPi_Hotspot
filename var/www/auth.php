<html>
<body>

<?php
$query_ip = "";
$query_user = $query_password = "";
$arp = "/usr/sbin/arp";
global $query_mac;

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Firstly, get user's IP, MAC, SERVER_NAME
    // 1. IP: http://devco.re/blog/2014/06/19/client-ip-detection/
    if (!empty($_SERVER["HTTP_CLIENT_IP"])) {
        $query_ip = $_SERVER["HTTP_CLIENT_IP"];
    } else if (!empty($_SERVER["HTTP_X_FORWARDED_FOR"])) {
        $query_ip = $_SERVER["HTTP_X_FORWARDED_FOR"];
    } else if (!empty($_SERVER["HTTP_X_FORWARDED"])) {
        $query_ip = $_SERVER["HTTP_X_FORWARDED"];
    } else if (!empty($_SERVER["HTTP_X_CLUSTER_CLIENT_IP"])) {
        $query_ip = $_SERVER["HTTP_X_CLUSTER_CLIENT_IP"];
    } else if (!empty($_SERVER["HTTP_FORWARDED_FOR"])) {
        $query_ip = $_SERVER["HTTP_FORWARDED_FOR"];
    } else if (!empty($_SERVER["HTTP_FORWARDED"])) {
        $query_ip = $_SERVER["HTTP_FORWARDED"];
    } else if (!empty($_SERVER["REMOTE_ADDR"])) {
        $query_ip = $_SERVER["REMOTE_ADDR"];
    } else {
        exit;
        // <TODO> if a masquerade IP, do nothing
    }

    $query_mac = shell_exec("$arp -a $query_ip");
    preg_match('/..:..:..:..:..:../', $query_mac, $matches);
    @$query_mac = $matches[0];
    if (!isset($query_mac)) {
        exit; 
    } else {
       $query_mac = strtoupper($query_mac); 
    }
    // <TODO> Remove below two lines
    echo "_SERVER['SERVER_NAME'] = " . $_SERVER['SERVER_NAME'] . "<br />";
    echo "User IP =  $query_ip, MAC = $query_mac <br />";

    // 2. Check user/password input from users, and verify its correctness
	$query_user = checkInput($_POST["user"]);
	$query_password = checkInput($_POST["password"]); 
	if (($query_user != NULL) && ($query_password != NULL)) {
		echo "=============== Debug Mode ===============<br />";
		echo "Original username: " . $_POST["user"] . "<br />";
		echo "Original password: " . $_POST["password"] . "<br />";
		echo "<br />";
		echo "username after check: " . $query_user . "<br />";
		echo "password after check: " . $query_password . "<br />";
		echo "==========================================<br />";
		try {
			// Process users in userLists.sqlite3.db
			$file_db = "";
			date_default_timezone_set("Asia/Taipei");
			try {
				// Create (connect to) SQLite database in file
				$file_db = new PDO("sqlite:/var/www/DB/userLists.sqlite3.db");
				// Set errormode to exceptions
				$file_db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
				// Create tables
				$file_db->exec("Create TABLE IF NOT EXISTS authUsers (id INTEGER PRIMARY KEY, user TEXT, password TEXT, reg_time TEXT, log_time TEXT)");
			} catch(PDOException $e) {
				// Print PDOException message
				echo $e->getMessage();
				exit;
			}
			$query_command = sprintf("SELECT id FROM authUsers WHERE user='%s' AND password='%s'", $query_user, $query_password);
			$result = $file_db->query($query_command);
			
			if ($result_row = $result->fetchObject()) {
				// Prepare UPDATE statement
				$update = sprintf("UPDATE authUsers SET log_time = :log_time WHERE id='%s'", $result_row->id);
				$stmt = $file_db->prepare($update);
				// Bind values directly to statement variables
				$time = date("Y-m-d H:i:s");
				$stmt->bindValue(':log_time', $time, SQLITE3_TEXT);
				// Execute statement
				$stmt->execute();
				
				displayDB($file_db);
				// Do Capital Portal Here
				// Show the logged in message or directly redirect to other website
                enableMAC();
            } else {
				echo "Access denied.<br />";
                // <TODO> Save denied account/password, which can be a reference of hack
				/* // Prepare INSERT statement to SQLite3 file db
				$insert = "INSERT INTO authUsers (user, password, reg_time, log_time) VALUES (:user, :password, :reg_time, :log_time)";
				$stmt = $file_db->prepare($insert);
				// Bind parameters to statement variables
				$stmt->bindParam(":user", $query_user);
				$stmt->bindParam(":password", $query_password);
				$time = date("Y-m-d H:i:s");
				$stmt->bindParam(":reg_time", $time);
				$stmt->bindParam(":log_time", $time);
				// Execute statement
				$stmt->execute(); */
			}
			
			$file_db = null; 
		} catch(Exception  $e) {
			// Print Exception message
			echo $e->getMessage();
			exit;
		}
		exit;
	} else {
		echo "[NULL] Access denied.<br />";
		exit;
	}
} else {
	echo "[GET] Access denied.<br />";
	exit;
}

/* function redirectPage() {
	static $num_attempt = 0;
	echo ++$num_attempt;
	$url = "http://" . $_SERVER['HTTP_HOST'];
	header("location: $url");
} */

function checkInput($data) {
	$data = trim($data);
	$data = stripslashes($data);
	$data = htmlspecialchars($data);
	return $data;
}

function enableMAC() {
    global $query_ip;
    global $query_mac;
    echo "[Debug]: A user with IP = $query_ip, MAC = $query_mac<br />";
    $test = shell_exec("sudo iptables -t mangle -L -n | grep $query_mac");
    echo "<pre>$test</pre><br />";
    if (empty($test)) {
        // Add permitted user to the WHITELIST
        shell_exec("sudo iptables -t mangle -I WHITELIST 1 -m mac --mac-source $query_mac -j RETURN");
    }
    $output = shell_exec("sudo iptables -t mangle -L -n");
    echo "<pre>$output</pre><br />";
    sleep(1);
    exit;
}

function displayDB($db) {
	$result = $db->query("SELECT * FROM authUsers");
	displayResult($result);
}

function displayResult($result) {
	printf("<pre>%5s %21s %19s %19s<br />", "ID", "Username/Password", "Registerd Time", "Logging Time");
	printf("----- --------------------- ------------------- -------------------<br />");
	foreach ($result as $row) {
		printf("%5s %21s %19s %19s<br />", $row["id"], $row["user"] . '/' . $row["password"], $row["reg_time"], $row["log_time"]);
	}
	echo "<pre/>";
}

function isNULL($result) {
	if ($result->fetchObject()) {
		return TRUE;
	} else {
		return FALSE;
	}
}

?>

</body>
</html>
