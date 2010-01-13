<%@ Page Language="C#" MasterPageFile="~/Views/Shared/index.master" Inherits="System.Web.Mvc.ViewPage" %>
<asp:Content ID="defaultContent" ContentPlaceHolderID="MainContent" runat="server">
    <asp:LoginView ID="lgnView" runat="server">
        <AnonymousTemplate>
            <h3>
                <%=this.ViewContext.Controller.ToString() %>
            </h3>
            <form id="apsnetForm" name="apsnetForm" runat="server">
            <asp:Login ID="ctlLogin" runat="server">
            </asp:Login>
            </form>
        </AnonymousTemplate>
        <LoggedInTemplate>
            <h3>
                <%=this.ViewContext.Controller.ToString() %>
            </h3>
        </LoggedInTemplate>
    </asp:LoginView>
</asp:Content>
