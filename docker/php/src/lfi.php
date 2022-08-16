<div>
  Include a local file with ?page={something.php}
  <br>
<?php
if (isset($_REQUEST['page'])) {
    include $_REQUEST['page'];
} else {
    include 'index.php';
}
?>
</div>