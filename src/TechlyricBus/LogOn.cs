using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;

namespace TechlyricBus
{
    [HandleError]
    public class LogOnController : Controller
    {
        public LogOnController()
        {
        }

        public ActionResult Index()
        {
            return View();
        }
    }
}
