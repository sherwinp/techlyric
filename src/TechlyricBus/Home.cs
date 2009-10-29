using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;

namespace TechlyricBus
{
    [HandleError]
    public class HomeController : System.Web.Mvc.Controller
    {
        public HomeController()
        {
        }

        public ActionResult Index()
        {
            return View();
        }
        [OutputCache(Duration=60, VaryByParam="none")]
        [ValidateInput(false)]
        public FileStreamResult ThreatLevel()
        {
            Uri url = new Uri("http://www.dhs.gov/threat_level/current_new.gif");
            WebRequest webrequest = WebRequest.Create(url);
            WebResponse webresponse = webrequest.GetResponse();
            return new FileStreamResult(webresponse.GetResponseStream(), "image/gif");
        }
    }
}
