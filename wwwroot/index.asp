<%@ Language="VBScript"%> 
<%Option Explicit%>
<% Dim strVarName %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <style type="text/css">
        #debugtab { font-family:Verdana; font-size:7pt; font-style:normal; }
    </style>
    <title>Test Page</title>
</head>
<body>
    <form id="aspform" runat="server">
    <table id="debugtab" border="1">
    <tr>
        <th>
            variable
        </th>
        <th>
            value
        </th>
    </tr>
    <% For Each strVarName in Request.ServerVariables %>
    <tr>
        <td>
            <%=strVarName%>
        </td>
        <td>
            <%=Request.ServerVariables(strVarName)%>&nbsp;</td>
    </tr>
    <% Next %>
</table>
    </form>
</body>
</html>
