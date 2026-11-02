using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Globalization;

using NodaTime;
using Geralt;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Models.Authentication;
using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Authorization;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Services;
using treehammock.RiggingSupport.Status;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.Entities;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.Rigging.Security;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Replay;
using treehammock.Models.Api;

namespace treehammock.Controllers;

public abstract partial class AccountControllerBase
{    protected ContentResult AccountVerificationContent(string html)
    {
        return Content(html, "text/html", Encoding.UTF8);
    }


    protected static bool VerificationPayloadMatchesRecord(string payload, string verifyKeyHash)
    {
        string payloadHash = AccountVerificationTokenUtility.HashToken(payload);
        byte[] payloadHashBytes = Encoding.UTF8.GetBytes(payloadHash);
        byte[] verifyKeyHashBytes = Encoding.UTF8.GetBytes(verifyKeyHash);
        return payloadHashBytes.Length == verifyKeyHashBytes.Length && CryptographicOperations.FixedTimeEquals(payloadHashBytes, verifyKeyHashBytes);
    }

}
