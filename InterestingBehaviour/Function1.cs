using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

using Sievo.Security;

using System;
using System.Threading.Tasks;

namespace InterestingBehaviour
{
    public static class Function1
    {
        [FunctionName("GetToken")]
        public static async Task<IActionResult> GetToken(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");
            try
            {
                var token = JwtToken.Create();
                return new OkObjectResult("Now, try again.");
            }
            catch (Exception e)
            {
                return new OkObjectResult(e.ToString());
            }
        }
    }
}
