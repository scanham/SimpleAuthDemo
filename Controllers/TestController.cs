using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;

namespace SimpleAuthDemo.Controllers
{
    [Route("[controller]")]
    public class TestController : Controller
    {
        private readonly IHttpClientFactory _httpFactory;
        public TestController(IHttpClientFactory httpFactory)
        {
            _httpFactory = httpFactory;
        }

        [Route("health")]
        public ActionResult Check(bool? verbose)
        {
            return Content("OK");
        }

        [Route("headers")]
        public ActionResult HeaderDump()
        {
            var pairs = Request.Headers.Select(x => x).ToList();
            return Json(pairs);
        }

        [Route("name")]
        public ActionResult Name()
        {
            if (User?.Claims?.Any() ?? false)
                return Json(User.Claims.FirstOrDefault(x => x.Type == "name").Value);
            return Json("Unknown");
        }
    }
}
