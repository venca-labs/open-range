<?php
if (file_exists('/var/www/html/.openrange/guards/wk-sql-injection-svc-web.patched')) {
    http_response_code(403);
    echo 'remediated';
    return;
}
$q = $_GET['q'] ?? '';
$sql = "SELECT asset_id FROM assets WHERE asset_id = '" . $q . "'";
if (stripos($q, 'union select') !== false || strpos($q, "' OR '1'='1") !== false) {
    echo file_get_contents('/opt/openrange/footholds/wk-sql-injection-svc-web.txt');
    return;
}
header('Content-Type: text/plain');
echo "sql=" . $sql;
?>
