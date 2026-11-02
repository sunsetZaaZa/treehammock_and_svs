using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using NSubstitute;
using Shouldly;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Services;
using treehammock.Entities;
using treehammock.Rigging.Security;
using treehammock.Rigging.Dependencies;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite","SqlContracts")]
public class Cor12DeliveryOutboxTests
{
    [Theory]
    [InlineData(0,12,1,16,true)]
    [InlineData(1,12,1,16,false)]
    [InlineData(2,12,1,16,false)]
    [InlineData(3,12,1,16,false)]
    [InlineData(4,12,1,16,false)]
    [InlineData(5,12,1,16,false)]
    [InlineData(6,12,1,16,false)]
    [InlineData(7,12,1,16,true)]
    [InlineData(7,11,1,16,false)]
    [InlineData(7,12,0,16,false)]
    [InlineData(7,12,65537,16,false)]
    [InlineData(7,12,1,15,false)]
    public async Task Payload_constraint_rejects_every_partial_null_tuple_and_invalid_length(int mask,int nonceLength,int cipherLength,int tagLength,bool valid)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>
        {
            var c=await f.OpenConnectionAsync(t);Guid id=Guid.NewGuid();
            await Exec(c,$"insert into accounts(account_id,email_address,security_stamp) values('{Account}','shape@example.test','{Stamp}'); insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state) values('{id}','{Account}','{Stamp}','verify','shape',clock_timestamp()+interval '1 hour','{{}}','none','staged')",t);
            await using var command=new NpgsqlCommand("insert into delivery_outbox(delivery_id,state,key_version,nonce,ciphertext,tag) values(@id,'queued',1,@nonce,@cipher,@tag)",c);
            command.Parameters.AddWithValue("id",id);
            command.Parameters.Add("nonce",NpgsqlTypes.NpgsqlDbType.Bytea).Value=(mask&1)!=0?(object)new byte[nonceLength]:DBNull.Value;
            command.Parameters.Add("cipher",NpgsqlTypes.NpgsqlDbType.Bytea).Value=(mask&2)!=0?(object)new byte[cipherLength]:DBNull.Value;
            command.Parameters.Add("tag",NpgsqlTypes.NpgsqlDbType.Bytea).Value=(mask&4)!=0?(object)new byte[tagLength]:DBNull.Value;
            if(valid)(await command.ExecuteNonQueryAsync(t)).ShouldBe(1);
            else
            {
                var error=await Should.ThrowAsync<PostgresException>(()=>command.ExecuteNonQueryAsync(t));
                error.SqlState.ShouldBe("23514");error.ConstraintName.ShouldBe("ck_delivery_payload");
            }
            (await Read<long>(c,"select count(*) from delivery_outbox",t)).ShouldBe(valid?1L:0L);
        });
    }

    private static readonly Guid Account=Guid.Parse("00000000-0000-0000-0000-000000001212");
    private static readonly Guid Stamp=Guid.Parse("00000000-0000-0000-0000-000000001213");
    private static readonly Guid Epoch=Guid.Parse("00000000-0000-0000-0000-000000001214");
    private static readonly Guid Parent=Guid.Parse("00000000-0000-0000-0000-000000001215");
    private static readonly string[] Purposes=["verify","unlock","reset","email","delete","factor-1","factor-2","reset-factor"];
    public static IEnumerable<object[]> Outcomes=>Purposes.SelectMany(p=>new[]{"rejected","ambiguous","expired"}.Select(o=>new object[]{p,o}));
    public static IEnumerable<object[]> Flows=>Purposes.Select(p=>new object[]{p});
    private static IOptions<DeliveryOutboxSettings> Settings()=>Options.Create(new DeliveryOutboxSettings {EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])}}});
    private static async Task<T> Read<T>(NpgsqlConnection c,string sql,CancellationToken token,NpgsqlTransaction? transaction=null)
    {await using var command=new NpgsqlCommand(sql,c,transaction);return (T)(await command.ExecuteScalarAsync(token))!;}
    private static async Task Exec(NpgsqlConnection c,string sql,CancellationToken token)
    {await using var command=new NpgsqlCommand(sql,c);await command.ExecuteNonQueryAsync(token);}
    private static string Predecessor(string purpose)=>$"select cor12_delivery_predecessor('{Account}','{purpose}')";
    private static async Task Seed(NpgsqlConnection c,string purpose,CancellationToken token)
    {
        await Exec(c,$"insert into accounts(account_id,email_address,security_stamp,verify_status,unlock_when) values('{Account}','reader@example.test','{Stamp}',1,clock_timestamp()+interval '4 hours'); insert into account_login_attempt_versions values('{Account}','{Stamp}','{Epoch}')",token);
        if(purpose=="reset-factor") await Exec(c,$"insert into two_factor_authentications(two_factor_index,account_id,method,verified,phone_number,phone_country_code) values(1,'{Account}',2,true,'5555550101','1')",token);
        await Cor17EmailSql.Install(c,token);
        await Cor18DeleteSql.Install(c,token);
        if(purpose is "email" or "delete" or "factor-1" or "factor-2") await Exec(c,$"update accounts set unlock_when=null where account_id='{Account}'",token);
        string reset=$"select result from create_password_reset_request('{Parent}','{Account}','email','email','old-reset',1,'fingerprint','r***r@example.test',true,false,clock_timestamp()+interval '4 hours',5,null,null,'{Stamp}')";
        string sql=purpose switch {
            "verify"=>$"update accounts set verify_status=0 where account_id='{Account}'; select result from resend_verify_account('reader@example.test','old-proof',interval '4 hours')",
            "unlock"=>$"select status from start_unlock_account('{Account}','old-proof',clock_timestamp(),clock_timestamp()+interval '4 hours',2::smallint,1::smallint,'{Stamp}',(select unlock_when from accounts where account_id='{Account}'),'{Epoch}')",
            "email"=>$"select result from cor17_fixture_request_email('{Account}','{Stamp}','old@example.test','old-proof',clock_timestamp()+interval '4 hours')",
            "delete"=>$"select result from cor18_fixture_request_delete('{Account}','{Stamp}',null,'old-proof',clock_timestamp()+interval '4 hours',interval '1 second',interval '1 hour',8::smallint);update account_delete_budgets set next_request_allowed_at=clock_timestamp()-interval '1 second' where account_id='{Account}'",
            "reset"=>reset,
            "reset-factor"=>reset+"; "+Cor13ResetSql.Bootstrap(Account.ToString(),Parent.ToString(),"session-hash")+"; "+Cor13ResetSql.Transition("session-hash",2,1,0,Cor13ResetSql.Select(1,"old-proof")),
            _=>"select true"
        };
        await Exec(c,sql,token);
        if(purpose is "factor-1" or "factor-2") {
            int method=purpose[^1]-'0';var g=await Cor16EnrollmentSql.SeedGrant(c,Account,Stamp,method==1?3:4,token);
            (await Read<bool>(c,Cor16EnrollmentSql.Begin(Account,Stamp,method,"old-proof",Guid.NewGuid(),g),token)).ShouldBeTrue();
        }
    }
    private static async Task<DeliveryIntent> Intent(NpgsqlConnection c,string purpose,string hash,CancellationToken token)
    {
        var now=SystemClock.Instance.GetCurrentInstant();
        object metadata=purpose switch {
            "verify"=>new {mode="resend",verificationSeconds=3600},
            "unlock"=>new {method=1,lockoutUnlockWhen=Instant.FromDateTimeUtc(await Read<DateTime>(c,$"select unlock_when from accounts where account_id='{Account}'",token)),lockoutAttemptVersion=Epoch},
            "email"=>new {newEmailAddress="new@example.test"},
            "delete"=>new {passPhraseHash=(string?)null,cooldownSeconds=1,windowSeconds=3600,maxRequests=8},
            "reset"=>new {resetId=Guid.NewGuid(),method="email",deliveryChannel="email",hashVersion=1,destinationFingerprint="fp",destinationMasked="r***r@example.test",requiresTotp=false,maxAttempts=5,requestedByIp=(string?)null,requestedByUserAgent=(string?)null},
            "reset-factor"=>new {transition=3,expectedSessionVersion=2L,expectedChallengeVersion=1L,resetId=Parent,sessionHash="session-hash",bootstrapProof=1,state=4,availableConfigurations=new[]{1},selectedConfiguration=1,requiredMethods=new[]{2},completedMethods=Array.Empty<int>(),currentExpectedMethod=2,challengeAttempts=0,challengeResends=2,nextChallengeAllowedAt=now,
                createdOn=Instant.FromDateTimeUtc(await Read<DateTime>(c,"select created_on from pending_password_reset_sessions",token)),
                expiresAt=Instant.FromDateTimeUtc(await Read<DateTime>(c,"select expires_at from pending_password_reset_sessions",token)),
                selectedAt=Instant.FromDateTimeUtc(await Read<DateTime>(c,"select selected_at from pending_password_reset_sessions",token)),twoFactorCompletedAt=(Instant?)null,passwordChangedAt=(Instant?)null},
            _=>new {emailAddress="reader@example.test",phoneNumber="5555550101",phoneCountryCode="1",required=true}
        };
        if(purpose is "factor-1" or "factor-2") {
            var g=await Cor16EnrollmentSql.SeedGrant(c,Account,Stamp,purpose=="factor-1"?3:4,token);
            Guid expected=await Read<Guid>(c,"select setup_request_id from two_factor_authentications where not verified",token);
            long version=await Read<long>(c,"select setup_version from two_factor_authentications where not verified",token);
            metadata=new {emailAddress="reader@example.test",phoneNumber="5555550101",phoneCountryCode="1",required=true,
                grantSession=g.Session,grantToken=g.Token,grantTarget=g.Target,expectedEnrollmentId=expected,expectedVersion=version};
        }
        DeliveryIntent? notice=null;
        if(purpose=="email") {
            var grant=await Cor16EnrollmentSql.SeedGrant(c,Account,Stamp,5,token);
            metadata=new {newEmailAddress="new@example.test",originEmail="reader@example.test",grantSession=grant.Session,grantToken=grant.Token,grantTarget=grant.Target};
            notice=new(Account,Stamp,"email-notice",hash,now.Plus(Duration.FromHours(1)),new {originEmail="reader@example.test",requestProofHash=hash},new("email-change-notice","email","reader@example.test","test","trusted-address-notice"));
        }
        if(purpose=="delete") {
            // Advance cooldown explicitly for this generic replacement fixture; COR18 owns budget schedules.
            await Exec(c,"update account_delete_budgets set next_request_allowed_at=clock_timestamp()-interval '1 second'",token);
            var g=await Cor16EnrollmentSql.SeedGrant(c,Account,Stamp,6,token);Guid admission=Guid.NewGuid();
            await using var admit=new NpgsqlCommand($"select result from cor18_admit_delete('{Account}','{Stamp}','{admission}','{hash}',@expires,interval '1 second',interval '1 hour',8::smallint,'{g.Session}','{g.Token}','{g.Target}')",c);
            admit.Parameters.AddWithValue("expires",now.Plus(Duration.FromHours(1)).ToDateTimeUtc());((bool)(await admit.ExecuteScalarAsync(token))!).ShouldBeTrue();
            metadata=new {admissionId=admission,passPhraseHash=(string?)null};
        }
        return new(Account,Stamp,purpose,hash,now.Plus(Duration.FromHours(1)),metadata,new("factor","email","reader@example.test","test","raw-secret-code"),notice);
    }
    private static async Task<ProtectedDelivery> Stage(SqlContractFixture f,NpgsqlConnection c,DeliveryPayloadProtector protector,string purpose,string hash,CancellationToken token)
    {
        var d=protector.Protect(await Intent(c,purpose,hash,token));
        await using var storage=Storage(f);
        var repo=new DeliveryOutboxRepo(storage,Settings());(await repo.StageAsync(d,token)).Result.ShouldBeTrue();
        if(purpose=="email") await Exec(c,"update delivery_candidates set state='published',terminal_at=clock_timestamp() where purpose='email-notice';update delivery_outbox o set state='published',nonce=null,ciphertext=null,tag=null from delivery_candidates q where o.delivery_id=q.delivery_id and q.purpose='email-notice'",token); // Explicit notification-publication fixture; COR17 owns provider schedules.
        return d;
    }
    private static Cor09RefreshHttpTests.FixtureStorage Storage(SqlContractFixture f)=>new(f,new SecurityOperationSettings {HmacKeys=new() {{1,Convert.ToBase64String(new byte[32])}}});

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Signup_account_inactive_proof_and_encrypted_job_commit_or_roll_back_together(bool invalidBinding)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var observer=await f.OpenConnectionAsync();await using var storage=Storage(f);
            var repo=new AccountRepo(new(Settings()),storage,Options.Create(new JWTSettings()),NullLogger<AccountRepo>.Instance,Substitute.For<IUserSecretHasher>());
            var now=SystemClock.Instance.GetCurrentInstant();
            var account=new Account(Account,"reader@example.test",null,[1],now,"web-key",VerificationStatus.STARTED);
            var intent=new DeliveryIntent(Account,Guid.Empty,invalidBinding?"delete":"verify","signup-hash",now.Plus(Duration.FromHours(1)),new {mode="start"},new("verify-start","email",account.emailAddress,"test","https://localhost.test/verify/raw-secret-code"));
            if(invalidBinding)
            {
                await Should.ThrowAsync<DependencyUnavailableException>(()=>repo.SetupAccount(account,"signup-hash",Period.FromHours(1),AccountSetupAction.EMAIL,intent,t));
                (await Read<long>(observer,"select count(*) from accounts",t)).ShouldBe(0L);
                (await Read<long>(observer,"select count(*) from account_verifications",t)).ShouldBe(0L);
                (await Read<long>(observer,"select count(*) from delivery_candidates",t)).ShouldBe(0L);
                (await Read<long>(observer,"select count(*) from delivery_outbox",t)).ShouldBe(0L);
            }
            else
            {
                var result=await repo.SetupAccount(account,"signup-hash",Period.FromHours(1),AccountSetupAction.EMAIL,intent,t);
                result.Item2.ShouldBe(HttpMessage.ACCOUNT_CREATION_SUCCESSED);
                (await Read<long>(observer,"select count(*) from accounts",t)).ShouldBe(1L);
                (await Read<long>(observer,"select count(*) from account_verifications where verify_status=0 and sent_when is null",t)).ShouldBe(1L);
                (await Read<long>(observer,"select count(*) from delivery_candidates c join delivery_outbox o using(delivery_id) join accounts a using(account_id) where c.account_stamp=a.security_stamp and c.state='staged' and o.state='queued' and o.ciphertext is not null",t)).ShouldBe(1L);
                (await Read<string>(observer,"select to_jsonb(s)::text from security_operation_steps s",t)).ShouldNotContain("raw-secret-code");
            }
        });
    }

    [Fact]
    public async Task Lost_staging_response_can_recover_same_inflight_job_without_replacing_or_sending()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var protector=new DeliveryPayloadProtector(Settings());
            var d=await Stage(f,c,protector,"verify","candidate-hash",t);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());
            var claimed=(await repo.ClaimAsync(t)).ShouldNotBeNull();
            (await repo.ExistingAsync(Account,Stamp,"verify",t)).ShouldBe(d.Id);
            var recovered=await repo.StageAsync(d,t);recovered.Result.ShouldBeTrue();recovered.DeliveryId.ShouldBe(d.Id);
            (await Read<long>(c,"select count(*) from delivery_outbox",t)).ShouldBe(1L);
            (await Read<string>(c,"select string_agg(to_jsonb(s)::text,',') from security_operation_steps s",t)).ShouldNotContain("raw-secret-code");
            protector.Open(claimed.Delivery).Value.ShouldBe("raw-secret-code");
            await repo.RecordAsync(claimed,new(DeliverySendState.Accepted,"accepted"),t);await repo.PublishAsync(d.Id,t);
            (await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("published");
        });
    }

    [Theory][MemberData(nameof(Outcomes))]
    public async Task Staging_and_nonacceptance_preserve_domain_contract(string purpose,string outcome)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,purpose,t);string before=await Read<string>(c,Predecessor(purpose),t);
            var d=await Stage(f,c,new(Settings()),purpose,"new-proof",t);
            if(purpose is "factor-1" or "factor-2" or "email" or "delete") {
                (await Read<string>(c,Predecessor(purpose),t)).ShouldNotBe(before);
                before=await Read<string>(c,Predecessor(purpose),t); // COR16 reserves the pending row before provider delivery.
            } else (await Read<string>(c,Predecessor(purpose),t)).ShouldBe(before);
            (await Read<bool>(c,$"select cor12_delivery_is_pending('{purpose}','new-proof','{Account}')",t)).ShouldBeTrue();
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();
            if(outcome=="expired") {await Exec(c,$"update delivery_candidates set expires_at=clock_timestamp()-interval '1 second' where delivery_id='{d.Id}'",t);await repo.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),t);}
            else await repo.RecordAsync(job,new(outcome=="ambiguous"?DeliverySendState.Unknown:DeliverySendState.Rejected,"test"),t);
            await repo.PublishAsync(d.Id,t);(await Read<string>(c,Predecessor(purpose),t)).ShouldBe(before);
            if(outcome!="ambiguous") (await Read<bool>(c,$"select ciphertext is null and nonce is null and tag is null from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBeTrue();
            else if(purpose is "factor-1" or "factor-2" or "email" or "delete") {
                (await repo.ClaimAsync(t)).ShouldBeNull();
                var attempted=purpose=="delete"?d with{Id=Guid.NewGuid(),ProofHash="later-proof"}:new DeliveryPayloadProtector(Settings()).Protect(await Intent(c,purpose,"later-proof",t));
                (await repo.StageAsync(attempted,t)).Result.ShouldBeFalse();
                (await Read<long>(c,"select count(*) from delivery_outbox",t)).ShouldBe(purpose=="email"?2L:1L);
            }
            else { (await repo.ClaimAsync(t)).ShouldBeNull();var candidate=await Stage(f,c,new(Settings()),purpose,"later-proof",t);(await Read<long>(c,"select count(*) from delivery_candidates where state='staged'",t)).ShouldBe(1L);(await Read<bool>(c,$"select exists(select 1 from delivery_candidates where delivery_id='{candidate.Id}')",t)).ShouldBeFalse(); }
        });
    }
    [Theory][MemberData(nameof(Flows))]
    public async Task Accepted_delivery_publishes_once_and_restart_does_not_resend(string purpose)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,purpose,t);string before=await Read<string>(c,Predecessor(purpose),t);
            var d=await Stage(f,c,new(Settings()),purpose,"new-proof",t);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();
            await repo.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),t);
            // Simulate process loss after acceptance persisted but before publication.
            var provider=new CountingProvider();var worker=new DeliveryOutboxWorker(new DeliveryOutboxRepo(storage,Settings()),new(Settings()),provider,Settings(),treehammock.Services.NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance);
            (await worker.ProcessOnceAsync(t)).ShouldBeTrue();provider.Calls.ShouldBe(0);
            (await Read<string>(c,Predecessor(purpose),t)).ShouldNotBe(before);
            (await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("published");
            (await worker.ProcessOnceAsync(t)).ShouldBeFalse();(await Read<bool>(c,$"select ciphertext is null from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBeTrue();
        });
    }
    [Theory][MemberData(nameof(Flows))]
    public async Task Superseded_queued_job_cannot_cancel_or_publish_new_candidate(string purpose)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,purpose,t);var protector=new DeliveryPayloadProtector(Settings());
            var old=await Stage(f,c,protector,purpose,"old-candidate",t);var current=await Stage(f,c,protector,purpose,"new-candidate",t);
            (await Read<bool>(c,$"select cor12_cancel_delivery('{old.Id}','{Account}','{Stamp}')",t)).ShouldBeFalse();
            (await Read<bool>(c,$"select cor12_publish_delivery('{old.Id}')",t)).ShouldBeFalse();
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();job.Delivery.Id.ShouldBe(current.Id);
            protector.Open(job.Delivery).Value.ShouldBe("raw-secret-code");
            await repo.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),t);await repo.PublishAsync(current.Id,t);
            (await Read<string>(c,$"select state from delivery_outbox where delivery_id='{current.Id}'",t)).ShouldBe("published");
        });
    }
    [Theory][MemberData(nameof(Flows))]
    public async Task Stamp_rotation_before_publication_preserves_old_working_proof(string purpose)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,purpose,t);var d=await Stage(f,c,new(Settings()),purpose,"new-proof",t);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();
            await repo.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),t);await Exec(c,$"update accounts set security_stamp=gen_random_uuid() where account_id='{Account}'",t);
            string before=await Read<string>(c,Predecessor(purpose),t);await repo.PublishAsync(d.Id,t);(await Read<string>(c,Predecessor(purpose),t)).ShouldBe(before);
            (await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe(purpose=="delete"?"expired":"superseded");
        });
    }
    [Fact]
    public async Task Lost_provider_result_reconciles_abandoned_claim_to_ambiguity_without_resending()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var d=await Stage(f,c,new(Settings()),"verify","new-proof",t);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();
            await Exec(c,$"update delivery_outbox set lease_until=clock_timestamp()-interval '1 second' where delivery_id='{d.Id}'",t);
            (await repo.ClaimAsync(t)).ShouldNotBeNull().State.ShouldBe("ambiguous");(await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("ambiguous");
            (await repo.ClaimAsync(t)).ShouldBeNull();
            // Known late acceptance is allowed only for this exact lease.
            (await Read<bool>(c,$"select cor12_record_delivery('{d.Id}','{Guid.NewGuid()}','accepted',3)",t)).ShouldBeFalse();
            await repo.RecordAsync(job,new(DeliverySendState.Accepted,"known-acceptance"),t);await repo.PublishAsync(d.Id,t);
            (await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("published");
        });
    }
    [Fact]
    public async Task Retry_uses_identical_job_and_code_and_stops_at_attempt_bound()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var protector=new DeliveryPayloadProtector(Settings());var d=await Stage(f,c,protector,"verify","new-proof",t);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());
            for(int i=0;i<3;i++){var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();job.Delivery.Id.ShouldBe(d.Id);protector.Open(job.Delivery).Value.ShouldBe("raw-secret-code");await repo.RecordAsync(job,new(DeliverySendState.NotSubmitted,"DELIVERY_RATE_LIMITED",true),t);await Exec(c,$"update delivery_outbox set next_attempt=clock_timestamp() where delivery_id='{d.Id}'",t);}
            (await repo.ClaimAsync(t)).ShouldBeNull();(await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("rejected");
        });
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Production_worker_handles_acceptance_and_provider_exception(bool throws)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var d=await Stage(f,c,new(Settings()),"verify","new-proof",t);var provider=new CountingProvider {Throws=throws};await using var storage=Storage(f);
            var worker=new DeliveryOutboxWorker(new DeliveryOutboxRepo(storage,Settings()),new(Settings()),provider,Settings(),treehammock.Services.NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance);(await worker.ProcessOnceAsync(t)).ShouldBeTrue();provider.Calls.ShouldBe(1);
            (await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe(throws?"ambiguous":"published");(await worker.ProcessOnceAsync(t)).ShouldBeFalse();provider.Calls.ShouldBe(1);
        });
    }
    [Theory][MemberData(nameof(Flows))]
    public async Task Changed_predecessor_before_publication_is_not_overwritten(string purpose)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,purpose,t);var d=await Stage(f,c,new(Settings()),purpose,"candidate",t);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();await repo.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),t);
            string mutation=purpose switch {
                "verify"=>$"update accounts set verify_status=1 where account_id='{Account}'",
                "unlock"=>$"update account_login_attempt_versions set attempt_version=gen_random_uuid() where account_id='{Account}'",
                "reset"=>$"update password_reset_requests set consumed_at=clock_timestamp() where account_id='{Account}'",
                "reset-factor"=>$"update pending_password_reset_sessions set challenge_attempts=challenge_attempts+1 where account_id='{Account}'",
                "email"=>$"delete from account_email_change_requests where account_id='{Account}'",
                "delete"=>$"update delete_standby set verified=true where account_id='{Account}'",
                _=>$"update two_factor_authentications set token='newer-working-proof' where account_id='{Account}'"
            };
            // A committed authoritative transition occurs after the provider accepted the candidate.
            await Exec(c,mutation,t);string current=await Read<string>(c,Predecessor(purpose),t);await repo.PublishAsync(d.Id,t);
            (await Read<string>(c,Predecessor(purpose),t)).ShouldBe(current);(await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe(purpose=="delete"?"expired":"superseded");
        });
    }
    [Fact]
    public async Task Publication_waiting_on_account_lock_rechecks_database_deadline()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var observer=await f.OpenConnectionAsync();await Seed(observer,"verify",t);var d=await Stage(f,observer,new(Settings()),"verify","candidate",t);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();await repo.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),t);
            var owner=await f.OpenConnectionAsync();var worker=await f.OpenConnectionAsync();await using var hold=await owner.BeginTransactionAsync(t);
            await using(var command=new NpgsqlCommand($"select cor02_lock_account_authority('{Account}','all');update delivery_candidates set expires_at=clock_timestamp()+interval '500 milliseconds' where delivery_id='{d.Id}'",owner,hold))await command.ExecuteNonQueryAsync(t);
            string before=await Read<string>(observer,Predecessor("verify"),t);var task=f.Observe(Read<bool>(worker,$"select cor12_publish_delivery('{d.Id}')",t));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,worker.ProcessID,owner.ProcessID,task,t);
            // Observe SQL time crossing the held, exclusive deadline instead of relying on an arbitrary delay.
            while(!await Read<bool>(owner,$"select expires_at<=clock_timestamp() from delivery_candidates where delivery_id='{d.Id}'",t,hold))await Task.Delay(10,t);
            await hold.CommitAsync(t);(await task).ShouldBeFalse();(await Read<string>(observer,Predecessor("verify"),t)).ShouldBe(before);
            (await Read<bool>(observer,$"select state='expired' and ciphertext is null from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task Competing_stage_waits_for_account_authority_and_leaves_one_current_job()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var observer=await f.OpenConnectionAsync();await Seed(observer,"verify",t);var owner=await f.OpenConnectionAsync();var worker=await f.OpenConnectionAsync();
            var first=new DeliveryPayloadProtector(Settings()).Protect(await Intent(observer,"verify","first-candidate",t));
            var second=new DeliveryPayloadProtector(Settings()).Protect(await Intent(observer,"verify","second-candidate",t));
            await using var hold=await owner.BeginTransactionAsync(t);await using(var gate=new NpgsqlCommand($"select cor02_lock_account_authority('{Account}','all')",owner,hold))await gate.ExecuteNonQueryAsync(t);
            // Raw SQL uses UTC timestamps because this observer fixture is deliberately a basic Npgsql connection.
            async Task<DeliveryStageResult> StageHere(NpgsqlConnection connection,ProtectedDelivery d,NpgsqlTransaction? transaction)
            {
                await using var command=new NpgsqlCommand("select result,code,delivery_id from cor12_stage_delivery(@id,@account,@stamp,@purpose,@hash,@expires,@metadata,@key,@nonce,@cipher,@tag)",connection,transaction);
                command.Parameters.AddWithValue("id",d.Id);command.Parameters.AddWithValue("account",d.AccountId);command.Parameters.AddWithValue("stamp",d.AccountStamp);command.Parameters.AddWithValue("purpose",d.Purpose);command.Parameters.AddWithValue("hash",d.ProofHash);command.Parameters.AddWithValue("expires",d.ExpiresAt.ToDateTimeUtc());command.Parameters.AddWithValue("metadata",d.MetadataJson);command.Parameters.AddWithValue("key",d.KeyVersion);command.Parameters.AddWithValue("nonce",d.Nonce);command.Parameters.AddWithValue("cipher",d.Ciphertext);command.Parameters.AddWithValue("tag",d.Tag);
                await using var reader=await command.ExecuteReaderAsync(t);await reader.ReadAsync(t);return new(reader.GetBoolean(0),reader.GetString(1),reader.GetGuid(2));
            }
            (await StageHere(owner,first,hold)).Result.ShouldBeTrue();var task=f.Observe(StageHere(worker,second,null));await SqlInterleavingBarrier.WaitForBlockedAsync(observer,worker.ProcessID,owner.ProcessID,task,t);
            await hold.CommitAsync(t);(await task).Result.ShouldBeTrue();
            (await Read<long>(observer,"select count(*) from delivery_candidates where state='staged'",t)).ShouldBe(1L);(await Read<bool>(observer,$"select state='superseded' and ciphertext is null from delivery_outbox where delivery_id='{first.Id}'",t)).ShouldBeTrue();
            (await Read<bool>(observer,$"select exists(select 1 from account_verifications where verify_key_hash='old-proof' and verify_status=4)",t)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task Expired_ambiguity_is_drained_and_encrypted_payload_is_erased()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var d=await Stage(f,c,new(Settings()),"verify","candidate",t);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();await repo.RecordAsync(job,new(DeliverySendState.Unknown,"unknown"),t);
            await Exec(c,$"update delivery_candidates set expires_at=clock_timestamp()-interval '1 second' where delivery_id='{d.Id}'",t);
            var provider=new CountingProvider();var worker=new DeliveryOutboxWorker(repo,new(Settings()),provider,Settings(),treehammock.Services.NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance);
            (await worker.ProcessOnceAsync(t)).ShouldBeTrue();provider.Calls.ShouldBe(0);(await Read<bool>(c,$"select state='expired' and ciphertext is null and nonce is null and tag is null from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBeTrue();
        });
    }


    [Theory]
    [InlineData("verify")][InlineData("unlock")][InlineData("reset")][InlineData("email")]
    [InlineData("delete")][InlineData("factor-1")][InlineData("factor-2")][InlineData("reset-factor")]
    public async Task Cor23I_unknown_acceptance_retains_encrypted_candidate_and_prior_proof_across_restart_until_expiry(string purpose)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var observer=await f.OpenConnectionAsync();await Seed(observer,purpose,t);var protector=new DeliveryPayloadProtector(Settings());
            var d=await Stage(f,observer,protector,purpose,"new-proof",t);string before=await Read<string>(observer,Predecessor(purpose),t);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var provider=new CountingProvider {Throws=true};
            var worker=new DeliveryOutboxWorker(repo,protector,provider,Settings(),NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance);
            (await worker.ProcessOnceAsync(t)).ShouldBeTrue();provider.Calls.ShouldBe(1);
            (await Read<string>(observer,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("ambiguous");
            (await Read<string>(observer,$"select state from delivery_attempts where delivery_id='{d.Id}'",t)).ShouldBe("unknown");
            (await Read<bool>(observer,$"select state='staged' and proof_hash='new-proof' and expires_at>clock_timestamp() from delivery_candidates where delivery_id='{d.Id}'",t)).ShouldBeTrue();
            (await Read<bool>(observer,$"select ciphertext is not null from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBeTrue();
            (await repo.ExistingAsync(Account,Stamp,purpose,t)).ShouldBe(d.Id);
            (await Read<bool>(observer,$"select cor12_delivery_is_pending('{purpose}','new-proof','{Account}')",t)).ShouldBeTrue();
            (await Read<string>(observer,Predecessor(purpose),t)).ShouldBe(before);
            var restarted=new DeliveryOutboxWorker(new DeliveryOutboxRepo(storage,Settings()),protector,provider,Settings(),NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance);
            (await restarted.ProcessOnceAsync(t)).ShouldBeFalse();provider.Calls.ShouldBe(1);
            (await repo.StageAsync(d,t)).Result.ShouldBeTrue();(await Read<long>(observer,$"select count(*) from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe(1);
            (await Read<string>(observer,$"select to_jsonb(a)::text from delivery_attempts a where delivery_id='{d.Id}'",t)).ShouldNotContain("raw-secret-code");
            await Exec(observer,$"update delivery_candidates set expires_at=clock_timestamp()-interval '1 second' where delivery_id='{d.Id}'",t);
            (await restarted.ProcessOnceAsync(t)).ShouldBeTrue();provider.Calls.ShouldBe(1);
            (await Read<bool>(observer,$"select ciphertext is null and lease_id is null from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBeTrue();
            (await Read<string>(observer,$"select state from delivery_candidates where delivery_id='{d.Id}'",t)).ShouldBe("expired");
            await Exec(observer,$"update delivery_candidates set terminal_at=clock_timestamp()-interval '8 days' where delivery_id='{d.Id}'",t);
            (await restarted.ProcessOnceAsync(t)).ShouldBeFalse();provider.Calls.ShouldBe(1);
            (await Read<long>(observer,$"select count(*) from delivery_attempts where delivery_id='{d.Id}'",t)).ShouldBe(0);
            (await Read<long>(observer,$"select count(*) from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe(0);
        });
    }
    [Fact]
    public async Task Cor23I_late_exact_accepted_receipt_resolves_only_its_attempt_and_replays_without_resend()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var d=await Stage(f,c,new(Settings()),"verify","candidate",t);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();
            (await repo.RecordAsync(job,new(DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN",Provider:"smtp"),t)).ShouldBeTrue();
            (await Read<bool>(c,$"select cor12_record_delivery('{d.Id}','{Guid.NewGuid()}','accepted',3)",t)).ShouldBeFalse();
            var accepted=new DeliverySendResult(DeliverySendState.Accepted,"DELIVERY_ACCEPTED",Provider:"smtp",ReceiptId:"receipt-123");
            (await repo.RecordAsync(job,accepted,t)).ShouldBeTrue();(await repo.PublishAsync(d.Id,t)).ShouldBeTrue();
            (await repo.RecordAsync(job,accepted,t)).ShouldBeTrue();(await repo.RecordAsync(job,accepted with {ReceiptId="different"},t)).ShouldBeFalse();
            var provider=new CountingProvider();var worker=new DeliveryOutboxWorker(repo,new(Settings()),provider,Settings(),NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance);
            (await worker.ProcessOnceAsync(t)).ShouldBeFalse();provider.Calls.ShouldBe(0);
            (await Read<string>(c,$"select receipt_id from delivery_attempts where attempt_id='{job.LeaseId}'",t)).ShouldBe("receipt-123");
            (await Read<long>(c,$"select count(*) from delivery_attempts where delivery_id='{d.Id}'",t)).ShouldBe(1);
        });
    }
    [Fact]
    public async Task Cor23I_unknown_cannot_be_requeued_by_a_generic_failure_or_invalid_outcome()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var d=await Stage(f,c,new(Settings()),"verify","candidate",t);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();
            await repo.RecordAsync(job,new(DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN"),t);
            (await repo.RecordAsync(job,new(DeliverySendState.NotSubmitted,"DELIVERY_RATE_LIMITED",true),t)).ShouldBeFalse();
            (await Read<bool>(c,$"select cor12_record_delivery('{d.Id}','{job.LeaseId}','garbage',3)",t)).ShouldBeFalse();
            (await Read<bool>(c,$"select cor12_record_delivery('{d.Id}','{job.LeaseId}','unknown',3,'none',null,true)",t)).ShouldBeFalse();
            (await repo.ClaimAsync(t)).ShouldBeNull();(await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("ambiguous");
        });
    }
    [Fact]
    public async Task Cor23I_confirmed_retry_keeps_one_job_and_proof_but_allocates_distinct_bounded_attempt_identities()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var protector=new DeliveryPayloadProtector(Settings());var d=await Stage(f,c,protector,"verify","candidate",t);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var ids=new HashSet<Guid>();
            for(int n=1;n<=3;n++)
            {
                var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();ids.Add(job.LeaseId!.Value).ShouldBeTrue();job.Attempts.ShouldBe(n);job.Delivery.Id.ShouldBe(d.Id);
                protector.Open(job.Delivery).Value.ShouldBe("raw-secret-code");await repo.RecordAsync(job,new(DeliverySendState.NotSubmitted,"DELIVERY_RATELIMITED",true,"twilio"),t);
                await Exec(c,$"update delivery_outbox set next_attempt=clock_timestamp() where delivery_id='{d.Id}'",t);
            }
            (await repo.ClaimAsync(t)).ShouldBeNull();(await Read<long>(c,$"select count(*) from delivery_attempts where delivery_id='{d.Id}' and state='not_submitted' and can_retry",t)).ShouldBe(3);
            (await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("rejected");
            (await Read<long>(c,$"select count(*) from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe(1);
            var error=await Should.ThrowAsync<PostgresException>(()=>Exec(c,$"update delivery_attempts set attempt_id=gen_random_uuid() where attempt_id='{ids.First()}'",t));error.SqlState.ShouldBe("P2301");
        });
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Cor23I_explicit_cancellation_or_expiry_prevents_a_late_receipt_resurrecting_proof(bool expired)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var d=await Stage(f,c,new(Settings()),"verify","candidate",t);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();await repo.RecordAsync(job,new(DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN"),t);
            if(expired)await Exec(c,$"update delivery_candidates set expires_at=clock_timestamp()-interval '1 second' where delivery_id='{d.Id}'",t);
            else (await Read<bool>(c,$"select cor12_cancel_delivery('{d.Id}','{Account}','{Stamp}')",t)).ShouldBeTrue();
            (await repo.RecordAsync(job,new(DeliverySendState.Accepted,"DELIVERY_ACCEPTED"),t)).ShouldBeFalse();(await repo.PublishAsync(d.Id,t)).ShouldBeFalse();
            (await Read<bool>(c,$"select ciphertext is null from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBeTrue();
            (await Read<string>(c,$"select state from delivery_attempts where attempt_id='{job.LeaseId}'",t)).ShouldBe("unknown");
        });
    }
    [Fact]
    public async Task Cor23I_crash_without_result_quarantines_the_same_attempt_and_preserves_definitive_receipt_immutability()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var d=await Stage(f,c,new(Settings()),"verify","candidate",t);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();
            await Exec(c,$"update delivery_outbox set lease_until=clock_timestamp()-interval '1 second' where delivery_id='{d.Id}'",t);
            (await repo.ClaimAsync(t)).ShouldNotBeNull().State.ShouldBe("ambiguous");(await Read<string>(c,$"select state from delivery_attempts where attempt_id='{job.LeaseId}'",t)).ShouldBe("unknown");
            (await repo.RecordAsync(job,new(DeliverySendState.Accepted,"DELIVERY_ACCEPTED",Provider:"smtp",ReceiptId:"late-receipt"),t)).ShouldBeTrue();await repo.PublishAsync(d.Id,t);
            var error=await Should.ThrowAsync<PostgresException>(()=>Exec(c,$"update delivery_attempts set receipt_id='replacement' where attempt_id='{job.LeaseId}'",t));error.SqlState.ShouldBe("P2301");
            (await repo.ClaimAsync(t)).ShouldBeNull();
        });
    }
    private sealed class LostHttpReceipt(string outcome) : System.Net.Http.HttpMessageHandler,IHttpClientFactory
    {
        public int Calls;
        public HttpClient CreateClient(string name)=>new(this,disposeHandler:false);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            Calls++; // Controlled provider accepted the POST; the client cannot infer this side effect from the reply.
            if(outcome=="lost")throw new IOException("accepted-then-acknowledgement-lost");
            return Task.FromResult(new HttpResponseMessage(outcome=="500"?System.Net.HttpStatusCode.InternalServerError:System.Net.HttpStatusCode.Created)
                {Content=new StringContent("{\"sid\":\"malformed\"}")});
        }
    }
    [Theory][InlineData("lost")][InlineData("malformed")][InlineData("500")]
    public async Task Cor23I_http_acceptance_uncertainty_reaches_SQL_quarantine_without_fallback_or_restart_send(string outcome)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);string before=await Read<string>(c,Predecessor("verify"),t);
            var protector=new DeliveryPayloadProtector(Settings());var intent=await Intent(c,"verify","candidate",t);
            var d=protector.Protect(intent with {Payload=intent.Payload with {Channel="sms",Destination="+15555550101"}});
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());(await repo.StageAsync(d,t)).Result.ShouldBeTrue();
            using var http=new LostHttpReceipt(outcome);var aws=Substitute.For<treehammock.Rigging.Sidewalk.IAWSService>();
            var config=Options.Create(new SidewalkSettings {SmsEnabled=true,TwilioEnabled=true,AwsSnsEnabled=true,SmsProviderPrimary="twilio",SmsProviderSecondary="aws-sns",TwilioAccountSid="AC0123456789abcdef0123456789abcdef",TwilioAuthToken="fixture",TwilioFromPhoneNumber="+15555550100"});
            var sender=new SmsSender(aws,new TwilioSmsService(new TwilioMessageClient(http),config),config);
            var adapter=new DeliveryProviderAdapter(Substitute.For<ISMTPService>(),sender);
            var worker=new DeliveryOutboxWorker(repo,protector,adapter,Settings(),NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance);
            (await worker.ProcessOnceAsync(t)).ShouldBeTrue();http.Calls.ShouldBe(1);
            (await Read<bool>(c,$"select state='ambiguous' and ciphertext is not null from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBeTrue();
            (await Read<string>(c,$"select state from delivery_attempts where delivery_id='{d.Id}'",t)).ShouldBe("unknown");
            (await Read<string>(c,Predecessor("verify"),t)).ShouldBe(before);
            var restarted=new DeliveryOutboxWorker(new DeliveryOutboxRepo(storage,Settings()),protector,adapter,Settings(),NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance);
            (await restarted.ProcessOnceAsync(t)).ShouldBeFalse();http.Calls.ShouldBe(1);
            await aws.DidNotReceiveWithAnyArgs().SendSMS(default!,default!,default);
        });
    }
    private static IOptions<DeliveryOutboxSettings> DeadlineSettings()=>Options.Create(new DeliveryOutboxSettings {ProviderTimeoutSeconds=1,ProviderAttemptTimeoutSeconds=1,CancellationDrainSeconds=1,MaxConcurrentSends=1,EncryptionKeys=new(){{1,Convert.ToBase64String(new byte[32])}}});
    private sealed class DeferredProvider : IDeliveryProvider
    {
        public int Calls;
        public readonly TaskCompletionSource<bool> Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource<DeliverySendResult> Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<DeliverySendResult> SendAsync(Guid attempt,DeliveryPayload payload,CancellationToken token){Calls++;Entered.TrySetResult(true);return Release.Task;}
    }
    private static async Task Eventually(Func<Task<bool>> condition,CancellationToken token)
    {
        using var bounded=CancellationTokenSource.CreateLinkedTokenSource(token);bounded.CancelAfter(TimeSpan.FromSeconds(8));
        while(!await condition())await Task.Delay(10,bounded.Token);
    }
    [Theory][InlineData("expiry")][InlineData("stamp")][InlineData("cancel")][InlineData("lease")][InlineData("unknown")]
    public async Task Cor23J_authority_recheck_rejects_expired_revoked_cancelled_wrong_lease_or_unknown_attempts(string change)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var d=await Stage(f,c,new(Settings()),"verify","candidate",t);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var job=(await repo.ClaimAsync(t)).ShouldNotBeNull();
            (await repo.CanSendAsync(job,t)).ShouldBeTrue();
            switch(change)
            {
                case "expiry":await Exec(c,$"update delivery_candidates set expires_at=clock_timestamp()-interval '1 second' where delivery_id='{d.Id}'",t);break;
                case "stamp":await Exec(c,$"update accounts set security_stamp=gen_random_uuid() where account_id='{Account}'",t);break;
                case "cancel":(await Read<bool>(c,$"select cor12_cancel_delivery('{d.Id}','{Account}','{Stamp}')",t)).ShouldBeTrue();break;
                case "lease":job=job with {LeaseId=Guid.NewGuid()};break;
                case "unknown":await repo.RecordAsync(job,new(DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN"),t);break;
            }
            (await repo.CanSendAsync(job,t)).ShouldBeFalse();
        });
    }
    [Fact]
    public async Task Cor23J_expiry_while_waiting_for_local_capacity_prevents_provider_work_and_erases_payload()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);
            var intent=await Intent(c,"verify","candidate",t);
            var d=new DeliveryPayloadProtector(Settings()).Protect(intent with {ExpiresAt=SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromSeconds(3))});
            var policy=new DeliveryExecutionPolicy(Settings());var occupied=new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);var entered=new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            // Occupy every configured slot; pending job lifetime is independent of these owned operations.
            var holds=Enumerable.Range(0,4).Select(_=>policy.RunAsync(t,b=>{entered.TrySetResult(true);return occupied.Task;},()=>-1,()=>-2)).ToArray();await entered.Task;
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());(await repo.StageAsync(d,t)).Result.ShouldBeTrue();var provider=new CountingProvider();var worker=new DeliveryOutboxWorker(repo,new(Settings()),provider,Settings(),NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance,policy);
            try
            {
                var run=worker.ProcessOnceAsync(t);
                await Eventually(async()=>await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)=="claimed",t);
                policy.ActiveOperations.ShouldBe(4);provider.Calls.ShouldBe(0);
                (await run).ShouldBeTrue();provider.Calls.ShouldBe(0);
                (await Read<bool>(c,$"select state='expired' and ciphertext is null from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBeTrue();
            }
            finally {occupied.TrySetResult(1);await Task.WhenAll(holds);}
            policy.ActiveOperations.ShouldBe(0);
        });
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Cor23J_noncooperative_provider_remains_owned_and_late_acceptance_respects_expiry_without_resend(bool expired)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var d=await Stage(f,c,new(Settings()),"verify","candidate",t);
            var settings=DeadlineSettings();var policy=new DeliveryExecutionPolicy(settings);var provider=new DeferredProvider();await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,settings);
            var worker=new DeliveryOutboxWorker(repo,new(settings),provider,settings,NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance,policy);
            try
            {
                (await worker.ProcessOnceAsync(t)).ShouldBeTrue();provider.Calls.ShouldBe(1);policy.ActiveOperations.ShouldBe(1);policy.AvailableCapacity.ShouldBe(0);
                (await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("ambiguous");(await worker.ProcessOnceAsync(t)).ShouldBeFalse();
                if(expired)await Exec(c,$"update delivery_candidates set expires_at=clock_timestamp()-interval '1 second' where delivery_id='{d.Id}'",t);
                provider.Release.TrySetResult(new(DeliverySendState.Accepted,"DELIVERY_ACCEPTED",Provider:"smtp",ReceiptId:"late-after-budget"));
                await Eventually(async()=>await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)==(expired?"expired":"published"),t);
                await Eventually(()=>Task.FromResult(policy.ActiveOperations==0),t);provider.Calls.ShouldBe(1);
                (await Read<long>(c,$"select count(*) from delivery_attempts where delivery_id='{d.Id}' and receipt_id='late-after-budget'",t)).ShouldBe(expired?0L:1L);policy.AvailableCapacity.ShouldBe(1);
            }
            finally {provider.Release.TrySetResult(new(DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN"));}
        });
    }
    private sealed class CancelAwareProvider(bool accepted) : IDeliveryProvider
    {
        public int Calls;public readonly TaskCompletionSource<bool> Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<DeliverySendResult> SendAsync(Guid id,DeliveryPayload payload,CancellationToken token)
        {
            Calls++;Entered.TrySetResult(true);
            try {await Task.Delay(Timeout.InfiniteTimeSpan,token);}catch(OperationCanceledException) when(token.IsCancellationRequested) { }
            return accepted?new(DeliverySendState.Accepted,"DELIVERY_ACCEPTED",Provider:"smtp",ReceiptId:id.ToString("N")):new(DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN");
        }
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Cor23J_shutdown_joins_transport_and_persists_accepted_or_unknown_with_an_independent_commit_budget(bool accepted)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var d=await Stage(f,c,new(Settings()),"verify","candidate",t);var settings=DeadlineSettings();var policy=new DeliveryExecutionPolicy(settings);var provider=new CancelAwareProvider(accepted);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,settings);var worker=new DeliveryOutboxWorker(repo,new(settings),provider,settings,NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance,policy);
            using var shutdown=new CancellationTokenSource();var work=worker.ProcessOnceAsync(shutdown.Token);await provider.Entered.Task;shutdown.Cancel();(await work).ShouldBeTrue();
            (await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe(accepted?"published":"ambiguous");policy.ActiveOperations.ShouldBe(0);provider.Calls.ShouldBe(1);
            (await Read<bool>(c,$"select ciphertext is null from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe(accepted);
        });
    }
    [Fact]
    public async Task Cor23J_committed_job_survives_client_request_cancellation_under_its_own_worker_lifetime()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var protector=new DeliveryPayloadProtector(Settings());var d=protector.Protect(await Intent(c,"verify","candidate",t));
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());using var request=new CancellationTokenSource();(await repo.StageAsync(d,request.Token)).Result.ShouldBeTrue();request.Cancel();
            var provider=new CountingProvider();var worker=new DeliveryOutboxWorker(repo,protector,provider,Settings(),NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance);
            (await worker.ProcessOnceAsync(t)).ShouldBeTrue();(await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("published");provider.Calls.ShouldBe(1);
        });
    }
    private sealed class RejectAndRevoke(Func<Task> revoke) : System.Net.Http.HttpMessageHandler,IHttpClientFactory
    {
        public int Calls;public HttpClient CreateClient(string name)=>new(this,disposeHandler:false);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {Calls++;await revoke();return new(System.Net.HttpStatusCode.BadRequest){Content=new StringContent("rejected")};}
    }
    [Fact]
    public async Task Cor23J_security_revocation_after_primary_rejection_prevents_the_secondary_provider_from_starting()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,"verify",t);var protector=new DeliveryPayloadProtector(Settings());var intent=await Intent(c,"verify","candidate",t);var d=protector.Protect(intent with {Payload=intent.Payload with {Channel="sms",Destination="+15555550101"}});
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());(await repo.StageAsync(d,t)).Result.ShouldBeTrue();
            using var http=new RejectAndRevoke(()=>Exec(c,$"update accounts set security_stamp=gen_random_uuid() where account_id='{Account}'",t));var aws=Substitute.For<treehammock.Rigging.Sidewalk.IAWSService>();
            var config=Options.Create(new SidewalkSettings {SmsEnabled=true,TwilioEnabled=true,AwsSnsEnabled=true,SmsProviderPrimary="twilio",SmsProviderSecondary="aws-sns",TwilioAccountSid="AC0123456789abcdef0123456789abcdef",TwilioAuthToken="fixture",TwilioFromPhoneNumber="+15555550100"});var policy=new DeliveryExecutionPolicy(Settings());
            var sender=new SmsSender(aws,new TwilioSmsService(new TwilioMessageClient(http),config),config,execution:policy);var worker=new DeliveryOutboxWorker(repo,protector,new DeliveryProviderAdapter(Substitute.For<ISMTPService>(),sender),Settings(),NullDeliveryAbuseThrottleService.Instance,NullLogger<DeliveryOutboxWorker>.Instance,policy);
            (await worker.ProcessOnceAsync(t)).ShouldBeTrue();http.Calls.ShouldBe(1);await aws.DidNotReceiveWithAnyArgs().SendSMS(default!,default!,default);
            (await Read<string>(c,$"select state from delivery_outbox where delivery_id='{d.Id}'",t)).ShouldBe("rejected");policy.ActiveOperations.ShouldBe(0);
        });
    }
    private sealed class CountingProvider : IDeliveryProvider
    {
        public int Calls;public bool Throws;
        public Task<DeliverySendResult> SendAsync(Guid id,DeliveryPayload p,CancellationToken t){Calls++;if(Throws)throw new IOException("provider response lost");return Task.FromResult(new DeliverySendResult(DeliverySendState.Accepted,"accepted"));}
    }
}
