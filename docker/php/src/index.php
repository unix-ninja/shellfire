<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Shellfire PHP Test App</title>
  <style>ul { max-width: 300px;} ol { padding:4px; color:white;font-weight:bold; text-decoration:underline; background:blue; margin-top:4px; } li { margin-top: 4px; } </style>
</head>
<body>
  <div>
    <h1>Shellfire PHP Test App</h1>
    <hr/>
    <ul>
      <ol>File Inclusion</ol>
      <li>
        <a href="/rfi.php">RFI Page</a>
      </li>
      <li>
        <a href="/lfi.php">LFI Page</a>
      </li>
      <ol>SSRF</ol>
      <li>
        <a href="/ssrf.php">file_get_contents SSRF Page</a>
      </li>
      <li>
        <a href="/curl_ssrf.php">cURL SSRF Page</a>
      </li>
    </ul>
  </div>
</body>
</html>