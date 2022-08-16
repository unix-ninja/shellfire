<?php
if (isset($_REQUEST['page'])) {
  $page = $_REQUEST['page'];
  include $page;
} else {
  include "rfi_default.php";
}
?>