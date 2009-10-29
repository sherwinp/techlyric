using System;   
using System.Collections.Generic;   
using System.Linq;   
using System.Web;   
using System.Web.Mvc;   
using System.Web.Routing;   


namespace TechlyricBus
{
    public class GlobalApplication : System.Web.HttpApplication
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");
            routes.MapRoute(
                "Default",
                "{controller}/{action}/{id}",
                new { controller = "Home", action = "Index", id = "" });

        }

        protected void Application_Start(object sender, EventArgs e)
        {
            //AppDomain.CurrentDomain.SetData("SQLServerCompactEditionUnderWebHosting", true);

            RegisterRoutes(RouteTable.Routes);
        }
    }
}