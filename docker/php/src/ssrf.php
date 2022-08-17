<div>
  Use with: <pre>ssrf.php?filename=ssrf.txt</pre>
  <hr/>
<pre>
<?php
  if (isset($_REQUEST['filename'])) {
    echo file_get_contents($_REQUEST['filename']);
  } else {
    echo file_get_contents('ssrf.txt');
  }
?>
</pre>
</div>