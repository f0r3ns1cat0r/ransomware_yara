<?php
function nr() { die('{"status":"not_running"}'); }
if ($_SERVER['REQUEST_METHOD'] == "POST") {
    header("Content-Type: application/json");
    $action = (isset($_POST['action'])) ? $_POST['action'] : false;
    if ($action === false) exit;
    switch($action) {
    case "decrypt":
        $key = (isset($_POST['key'])) ? $_POST['key'] : false;
        if($key === false) exit;
        if(strlen($key) !== 32) exit;
        for($i=0; $i<16; $i++) {
            $key_bin .= chr(hexdec(substr($key, $i*2, 2)));
        }
        $h = hash("sha256", $key_bin);
        if($h === "{KEYHASH}" || $h === "{MASTER_KEYHASH}") {
            $pid = pcntl_fork();
            if($pid == 0) {
                system("({PATH_TOOL}" . " -d " . $key . " " . "{PATH_CRYPT}) &");
            }
        } else {
            die('{"status":"wrong key"}');
        }
        break;
    case "status":
        if (file_exists("{PATH_FINISH_FILENAME}")) { die('{"status":"finished"}'); }
        if (file_exists("{PATH_PID_FILENAME}")) {
            $pid = trim(file_get_contents("{PATH_PID_FILENAME}"));
            if (empty($pid)) nr();
            if (!file_exists("/proc/".$pid)) nr();
            if (file_exists("{PATH_STATUS_FILENAME}")) {
                $c = trim(file_get_contents("{PATH_STATUS_FILENAME}"));
                die('{"status":"running","count":"'.$c.'"}');
            } else {
                nr();
            }
        } else {
            nr();
        }
        break;
    }
} else {
    echo base64_decode("{INDEX_PAGE}");
}
