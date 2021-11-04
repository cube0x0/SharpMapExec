using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Web.Script.Serialization;

namespace SharpMapExec.Lib
{
    // https://github.com/ustayready/SharpHose
    public class LDAPPasswordPolicy
    {
        public int LockoutThreshold { get; set; }
        public long LockoutDuration { get; set; }
        public long LockoutObservationWindow { get; set; }
        public int MinimumPasswordLength { get; set; }
        public long MinimumPasswordAge { get; set; }
        public long MaximumPasswordAge { get; set; }
        public bool PossiblyCustomized { get; set; }
        public string Name { get; set; }
        public bool IsFineGrained { get; set; }
        public int PasswordHistoryLength { get; set; }
        public List<string> AppliesToDN { get; set; }
        public int PasswordPrecendence { get; set; }
        public bool ComplexityEnabled { get; set; }
        public bool ReversibleEncryptionEnabled { get; set; }
        public string ADSPath { get; set; }
        public List<string> AppliesToUsers { get; set; }

        public LDAPPasswordPolicy(SearchResult result, bool isFineGrained)
        {
            AppliesToDN = new List<string>();
            AppliesToUsers = new List<string>();
            IsFineGrained = isFineGrained;

            if (isFineGrained)
            {
                LoadFineGrainedPolicy(result);
            }
            else
            {
                LoadDomainPolicy(result);
            }
        }

        private void LoadFineGrainedPolicy(SearchResult result)
        {
            foreach (DictionaryEntry prop in result.Properties)
            {
                var property = (string)prop.Key;
                var value = (ResultPropertyValueCollection)prop.Value;

                if (property == "msds-psoappliesto")
                {
                    foreach (string applies in (ResultPropertyValueCollection)value)
                    {
                        AppliesToDN.Add(applies);
                    }
                }
                else if (new string[] { "name", "adspath" }.Any(x => x == property))
                {
                    switch (property)
                    {
                        case "name":
                            Name = (string)value[0];
                            break;

                        case "adspath":
                            ADSPath = (string)value[0];
                            break;
                    }
                }
                else if (new string[] { "msds-passwordcomplexityenabled", "msds-passwordreversibleencryptionenabled" }.Any(x => x == property))
                {
                    bool placeHolder = (bool)value[0];
                    switch (property)
                    {
                        case "msds-passwordcomplexityenabled":
                            ComplexityEnabled = placeHolder;
                            break;

                        case "msds-passwordreversibleencryptionenabled":
                            ReversibleEncryptionEnabled = placeHolder;
                            break;
                    }
                }
                else if (new string[] { "msds-lockoutobservationwindow", "msds-lockoutduration", "msds-minimumpasswordage", "msds-maximumpasswordage" }.Any(x => x == property))
                {
                    long placeHolder = (long)value[0];
                    switch (property)
                    {
                        case "msds-lockoutobservationwindow":
                            LockoutObservationWindow = placeHolder;
                            break;

                        case "msds-lockoutduration":
                            LockoutDuration = placeHolder;
                            break;

                        case "msds-minimumpasswordage":
                            MinimumPasswordAge = placeHolder;
                            break;

                        case "msds-maximumpasswordage":
                            MaximumPasswordAge = placeHolder;
                            break;
                    }
                }
                else
                {
                    int placeHolder;
                    int.TryParse(value[0].ToString(), out placeHolder);

                    switch (property)
                    {
                        case "msds-lockoutthreshold":
                            LockoutThreshold = placeHolder;
                            break;

                        case "msds-minimumpasswordlength":
                            MinimumPasswordLength = placeHolder;
                            break;

                        case "msds-passwordhistorylength":
                            PasswordHistoryLength = placeHolder;
                            break;

                        case "msds-passwordsettingsprecedence":
                            PasswordPrecendence = placeHolder;
                            break;
                    }
                }
            }
        }

        public void LoadDomainPolicy(SearchResult result)
        {
            PasswordPrecendence = 0;

            foreach (DictionaryEntry prop in result.Properties)
            {
                var property = (string)prop.Key;
                var value = (ResultPropertyValueCollection)prop.Value;

                if (new string[] { "name", "adspath" }.Any(x => x == property))
                {
                    switch (property)
                    {
                        case "name":
                            Name = (string)value[0];
                            break;

                        case "adspath":
                            ADSPath = (string)value[0];
                            break;
                    }
                }
                else if (new string[] { "lockoutobservationwindow", "lockoutduration", "minpwdage", "maxpwdage" }.Any(x => x == property))
                {
                    long placeHolder = (long)value[0];
                    switch (property)
                    {
                        case "lockoutobservationwindow":
                            LockoutObservationWindow = placeHolder;
                            break;

                        case "lockoutduration":
                            LockoutDuration = placeHolder;
                            break;

                        case "minpwdage":
                            MinimumPasswordAge = placeHolder;
                            break;

                        case "maxpwdage":
                            MaximumPasswordAge = placeHolder;
                            break;
                    }
                }
                else
                {
                    int placeHolder;
                    int.TryParse(value[0].ToString(), out placeHolder);

                    switch (property)
                    {
                        case "lockoutthreshold":
                            LockoutThreshold = placeHolder;
                            break;

                        case "minpwdlength":
                            MinimumPasswordLength = placeHolder;
                            break;

                        case "pwdhistorylength":
                            PasswordHistoryLength = placeHolder;
                            break;

                        case "passwordsettingsprecedence":
                            PasswordPrecendence = placeHolder;
                            break;

                        case "msds-behavior-version":
                            PossiblyCustomized = placeHolder >= 3 ? true : false; ;
                            break;
                    }
                }
            }
        }
    }

    public class UserInfo
    {
        public virtual string Username { get; set; }
        public virtual Domain.UserState UserState { get; set; }
    }

    public class LDAPUserInfo : UserInfo
    {
        public override string Username { get; set; }

        public int BadPasswordCount { get; set; }
        public DateTime BadPasswordTime { get; set; }
        public DateTime LockoutTime { get; set; }
        public int LockoutDuration { get; set; }
        public DateTime PasswordLastSet { get; set; }
        public string PolicyName { get; set; }

        public LDAPUserInfo(SearchResult result)
        {
            Username = result.Properties["sAMAccountname"][0].ToString().ToLower();

            int badPwdCount = 0;
            if (result.Properties.Contains("badPwdCount"))
                int.TryParse(result.Properties["badPwdCount"][0].ToString(), out badPwdCount);
            BadPasswordCount = badPwdCount;

            long badPasswordTime = 0;
            if (result.Properties.Contains("badPasswordTime"))
                long.TryParse(result.Properties["badPasswordTime"][0].ToString(), out badPasswordTime);

            try
            {
                if (badPasswordTime != -1)
                    BadPasswordTime = DateTime.FromFileTime(badPasswordTime);
            }
            catch
            {
                throw new Exception($"Bad password time: {badPasswordTime} for {Username}");
            }

            long lockoutTime = 0;
            if (result.Properties.Contains("lockoutTime"))
                long.TryParse(result.Properties["lockoutTime"][0].ToString(), out lockoutTime);

            try
            {
                if (lockoutTime != -1)
                    LockoutTime = DateTime.FromFileTime(lockoutTime);
            }
            catch
            {
                throw new Exception($"Bad lockout time: {lockoutTime} for {Username}");
            }

            int lockoutDuration = 0;
            if (result.Properties.Contains("lockoutDuration"))
                int.TryParse(result.Properties["lockoutDuration"][0].ToString(), out lockoutDuration);
            LockoutDuration = lockoutDuration;

            long pwdLastSet = 0;
            if (result.Properties.Contains("pwdLastSet"))
                long.TryParse(result.Properties["pwdLastSet"][0].ToString(), out pwdLastSet);

            try
            {
                if (pwdLastSet != -1)
                    PasswordLastSet = DateTime.FromFileTime(pwdLastSet);
            }
            catch
            {
                throw new Exception($"Bad password last set time: {pwdLastSet} for {Username}");
            }
        }
    }

    public static class LDAPExtensions
    {
        public static LDAPPasswordPolicy GetUserPolicy(this LDAPUserInfo user, List<LDAPPasswordPolicy> Policies)
        {
            var policy = Policies
                .Where(x => x.IsFineGrained && x.AppliesToUsers.Contains(user.Username, StringComparer.OrdinalIgnoreCase))
                .OrderByDescending(y => y.PasswordPrecendence);

            if (policy.Count() > 0)
            {
                return policy.First();
            }
            else
            {
                return Policies.First(x => !x.IsFineGrained);
            }
        }

        public static LDAPUserInfo ClassifyUser(this LDAPUserInfo user, LDAPPasswordPolicy policy)
        {
            user.PolicyName = policy.Name;
            if (policy.LockoutThreshold == 0)
            {
                user.UserState = Domain.UserState.SAFE_TO_SPRAY;
                return user;
            }

            var now = DateTime.Now;
            var start = new DateTime(1900, 01, 01);
            var badPasswordCount = user.BadPasswordCount;
            var lockoutDurationTime = user.LockoutTime.AddTicks((policy.LockoutDuration * -1));
            var observationTime = user.BadPasswordTime.AddTicks((policy.LockoutObservationWindow * -1));

            if ((badPasswordCount == policy.LockoutThreshold) && (observationTime > now))
            {
                user.UserState = Domain.UserState.LOCKED_OUT;
            }
            else if (badPasswordCount == (policy.LockoutThreshold - 1))
            {
                user.UserState = Domain.UserState.PENDING_LOCK_OUT;
            }

            if (observationTime < now)
            {
                user.UserState = Domain.UserState.SAFE_TO_SPRAY;
                var diff = (policy.LockoutThreshold - 1);
            }
            else if ((badPasswordCount < (policy.LockoutThreshold - 1)) && (observationTime > now))
            {
                user.UserState = Domain.UserState.SAFE_TO_SPRAY;
                var diff = (policy.LockoutThreshold - 1) - badPasswordCount;
            }

            if (lockoutDurationTime < start)
            {
                // Never locked out
            }
            if ((lockoutDurationTime > start) && (observationTime < now))
            {
                // Was locked out
            }
            if ((badPasswordCount == (policy.LockoutThreshold - 1)) && (lockoutDurationTime < start) && (observationTime < now))
            {
                // Almost locked out
            }
            if ((badPasswordCount > 0) && (badPasswordCount < (policy.LockoutThreshold - 1)) && (observationTime < now))
            {
                // Prior failed attempts
            }
            return user;
        }
    }

    public class Domain
    {
        public enum UserState
        {
            LOCKED_OUT = 0,
            PENDING_LOCK_OUT = 1,
            SAFE_TO_SPRAY = 2,
            NOT_YET_KNOWN = 3
        }

        public static string[] GetList(List<LDAPPasswordPolicy> Policies, List<UserInfo> Users)
        {
            string[] users;
            var excluded = new List<string>();

            var removedUnsafe = Users.RemoveAll(x => x.UserState != UserState.SAFE_TO_SPRAY);

            var fineGrainedPoliciesUserCount = Policies
                .Where(x => x.IsFineGrained)
                .Sum(y => y.AppliesToUsers.Count());

            var defaultPolicyUserCount = Users.Count() - fineGrainedPoliciesUserCount;

            var removedExcluded = Users.RemoveAll(x => excluded.Contains(x.Username, StringComparer.OrdinalIgnoreCase));

            Console.WriteLine($"Default Policy: {defaultPolicyUserCount} total user(s)");
            Console.WriteLine($"Fine Grained Policies: {fineGrainedPoliciesUserCount} total user(s)");
            Console.WriteLine($"Removed {removedUnsafe} unsafe user(s)");
            Console.WriteLine($"Removed {removedExcluded} excluded user(s)");
            Console.WriteLine($"Spraying {Users.Count()} user(s)");
            Console.WriteLine($"-----------------------------------");
            Console.WriteLine();

            users = Users.Select(i => i.Username).ToArray();

            return users;
        }

        public static int DisplayPolicyUsers(string policyName, List<LDAPPasswordPolicy> Policies, List<UserInfo> Users, bool onlyCount = false)
        {
            var users = new List<string>();
            var policy = Policies.FirstOrDefault(x => x.Name.ToLower() == policyName.ToLower());

            if (policy != null)
            {
                if (policy.IsFineGrained)
                {
                    users = policy.AppliesToUsers;
                }
                else
                {
                    var domUsers = new List<string>();
                    Users.ForEach(x => domUsers.Add(x.Username));

                    var fgUsers = new List<string>();
                    Policies.Where(x => x.IsFineGrained).ToList()
                        .ForEach(p => p.AppliesToUsers.ForEach(x => fgUsers.Add(x)));

                    users = domUsers.Where(p => fgUsers.All(p2 => p2.ToLower() != p.ToLower()))
                        .Distinct().ToList();
                }
            }
            else
            {
                Console.WriteLine($"Policy not found: {policyName}");
            }
            return users.Count;
        }

        public static void DisplayPolicyDetails(LDAPPasswordPolicy policy, List<LDAPPasswordPolicy> Policies, List<UserInfo> Users)
        {
            var count = DisplayPolicyUsers(policy.Name, Policies, Users, true);

            var lockoutDurationTs = new TimeSpan(policy.LockoutDuration * -1);
            var lockoutObservationWindowTs = new TimeSpan(policy.LockoutObservationWindow * -1);
            var MinimumPasswordAgeTs = new TimeSpan(policy.MinimumPasswordAge * -1);
            var MaximumPasswordAgeTs = new TimeSpan(policy.MaximumPasswordAge * -1);

            Console.WriteLine($"-----------------------------------");
            Console.WriteLine($"Name: {policy.Name}");
            Console.WriteLine($"Order Precedence: {policy.PasswordPrecendence}");
            Console.WriteLine($"ADs Path: {policy.ADSPath}");
            Console.WriteLine($"Is Fine Grained? {policy.IsFineGrained}");
            if (policy.IsFineGrained) { Console.WriteLine($"Applied to: {policy.AppliesToUsers.Count} users"); }
            Console.WriteLine($"Minimum Password Length: {policy.MinimumPasswordLength}");
            Console.WriteLine($"Lockout Threshold: {policy.LockoutThreshold}");
            Console.WriteLine($"Lockout Duration: {string.Format("{0:%d}d {0:%h}h {0:%m}m {0:%s}s", lockoutDurationTs)}");
            Console.WriteLine($"Lockout Observation Window: {string.Format("{0:%d}d {0:%h}h {0:%m}m {0:%s}s", lockoutObservationWindowTs)}");
            Console.WriteLine($"Minimum / Maximum Password Age: {string.Format("{0:%d}d {0:%h}h {0:%m}m {0:%s}s", MinimumPasswordAgeTs)} / {string.Format("{0:%d}d {0:%h}h {0:%m}m {0:%s}s", MaximumPasswordAgeTs)}");
            Console.WriteLine($"Password History Length: {policy.PasswordHistoryLength}");
            Console.WriteLine($"Applies to: {count} users");
            Console.WriteLine();
        }

        public static List<string> GetPasswordPolicyUsers(LDAPPasswordPolicy policy, DirectoryEntry directoryObject)
        {
            Console.WriteLine($"[-] Retrieving users for policy: {policy.Name}");

            var users = new List<string>();
            policy.AppliesToDN.ForEach(a =>
            {
                var groupSearch = new DirectorySearcher(directoryObject);
                groupSearch.Filter = $"(&(objectCategory=user)(memberOf={a}))";
                groupSearch.PageSize = 1000;
                groupSearch.PropertiesToLoad.Add("sAMAccountName");
                groupSearch.SearchScope = SearchScope.Subtree;

                var groupResults = groupSearch.FindAll();
                if (groupResults.Count > 0)
                {
                    for (var i = 0; i < groupResults.Count; i++)
                    {
                        var username = (string)groupResults[i].Properties["sAMAccountname"][0];
                        users.Add(username.ToLower());
                    }
                }
                else
                {
                    var userSearch = new DirectorySearcher(directoryObject);
                    userSearch.Filter = $"(&(objectCategory=user)(distinguishedName={a}))";
                    userSearch.PageSize = 1000;
                    userSearch.PropertiesToLoad.Add("sAMAccountName");
                    userSearch.SearchScope = SearchScope.Subtree;
                    var userResults = userSearch.FindOne();

                    if (userResults != null)
                    {
                        var username = (string)userResults.Properties["sAMAccountname"][0];
                        users.Add(username.ToLower());
                    }
                }
            });
            return users;
        }

        static public LDAPPasswordPolicy GetDomainPolicy(DirectoryEntry directoryObject)
        {
            var searcher = new DirectorySearcher(directoryObject);
            searcher.SearchScope = SearchScope.Base;
            searcher.PropertiesToLoad.Add("name");
            searcher.PropertiesToLoad.Add("msds-behavior-version");
            searcher.PropertiesToLoad.Add("lockoutduration");
            searcher.PropertiesToLoad.Add("lockoutthreshold");
            searcher.PropertiesToLoad.Add("lockoutobservationwindow");
            searcher.PropertiesToLoad.Add("minpwdlength");
            searcher.PropertiesToLoad.Add("minpwdage");
            searcher.PropertiesToLoad.Add("maxpwdage");
            searcher.PropertiesToLoad.Add("pwdhistorylength");
            searcher.PropertiesToLoad.Add("adspath");
            searcher.PropertiesToLoad.Add("pwdproperties");

            var result = searcher.FindOne();
            var policy = new LDAPPasswordPolicy(result, false);
            policy.AppliesToUsers = new List<string>();

            return policy;
        }

        public static List<LDAPPasswordPolicy> GetFineGrainedPolicies(DirectoryEntry directoryObject)
        {
            var policies = new List<LDAPPasswordPolicy>();
            var policySearch = new DirectorySearcher(directoryObject);

            policySearch.Filter = $"(objectclass=msDS-PasswordSettings)";
            policySearch.PropertiesToLoad.Add("name");
            policySearch.PropertiesToLoad.Add("msds-lockoutthreshold");
            policySearch.PropertiesToLoad.Add("msds-psoappliesto");
            policySearch.PropertiesToLoad.Add("msds-minimumpasswordlength");
            policySearch.PropertiesToLoad.Add("msds-passwordhistorylength");
            policySearch.PropertiesToLoad.Add("msds-lockoutobservationwindow");
            policySearch.PropertiesToLoad.Add("msds-lockoutduration");
            policySearch.PropertiesToLoad.Add("msds-minimumpasswordage");
            policySearch.PropertiesToLoad.Add("msds-maximumpasswordage");
            policySearch.PropertiesToLoad.Add("msds-passwordsettingsprecedence");
            policySearch.PropertiesToLoad.Add("msds-passwordcomplexityenabled");
            policySearch.PropertiesToLoad.Add("msds-passwordreversibleencryptionenabled");

            var pwdPolicies = policySearch.FindAll();

            foreach (SearchResult result in pwdPolicies)
            {
                var policy = new LDAPPasswordPolicy(result, true);
                policy.AppliesToUsers = GetPasswordPolicyUsers(policy, directoryObject);
                policies.Add(policy);
            }

            return policies;
        }

        public static string BindPath(string domain, string domainController, string ou = "")
        {
            string bindPath = String.Format("LDAP://{0}", domainController);

            if (!String.IsNullOrEmpty(ou))
            {
                string ouPath = ou.Replace("ldap", "LDAP").Replace("LDAP://", "");
                bindPath = String.Format("{0}/{1}", bindPath, ouPath);
            }
            else if (!String.IsNullOrEmpty(domain))
            {
                string domainPath = domain.Replace(".", ",DC=");
                bindPath = String.Format("{0}/DC={1}", bindPath, domainPath);
            }

            return bindPath;
        }

        public static string FindDomainController(string domain)
        {
            var pingSender = new Ping();
            var options = new PingOptions();
            options.DontFragment = true;

            byte[] buffer = Encoding.ASCII.GetBytes(new string('A', 32));
            var reply = pingSender.Send(domain, 120, buffer, options);
            if (reply.Status == IPStatus.Success)
            {
                try
                {
                    return Dns.GetHostEntry(reply.Address.ToString()).HostName;
                }
                catch
                {
                    return reply.Address.ToString();
                }
            }
            else
            {
                return string.Empty;
            }
        }

        public static void GetUsers(string domain, string domainController = "", string ou = "")
        {
            if (string.IsNullOrEmpty(domainController))
                domainController = FindDomainController(domain);
            string bindPath = BindPath(domain, domainController);
            //Console.WriteLine(bindPath);
            
            DirectoryEntry directoryObject = new DirectoryEntry(bindPath);
            List<LDAPPasswordPolicy> Policies = new List<LDAPPasswordPolicy>();
            List<UserInfo> Users = new List<UserInfo>();

            DirectorySearcher userSearcher = new DirectorySearcher(directoryObject);
            userSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))";
            userSearcher.PropertiesToLoad.Add("sAMAccountName");
            userSearcher.PropertiesToLoad.Add("badPwdCount");
            userSearcher.PropertiesToLoad.Add("badPasswordTime");
            userSearcher.PropertiesToLoad.Add("lockoutTime");
            userSearcher.PropertiesToLoad.Add("lockoutDuration");
            userSearcher.PropertiesToLoad.Add("pwdLastSet");
            userSearcher.SearchScope = SearchScope.Subtree;

            try
            {
                //pass policy
                Policies.Add(GetDomainPolicy(directoryObject));

                var fineGrainedPolicies = GetFineGrainedPolicies(directoryObject);
                fineGrainedPolicies.ForEach(x => x.AppliesToUsers = GetPasswordPolicyUsers(x, directoryObject));
                Policies.AddRange(fineGrainedPolicies);

                //users
                SearchResultCollection users = userSearcher.FindAll();
                foreach (SearchResult user_ in users)
                {
                    LDAPPasswordPolicy policy;
                    var user = new LDAPUserInfo(user_);
                    policy = user.GetUserPolicy(Policies);
                    user = user.ClassifyUser(policy);
                    Users.Add(user);
                }

                Console.WriteLine($"[*] {Users.Count} users & {Policies.Count} policies found");
                Console.WriteLine("[*] Saving to users.json and policy.json to loot folder");
                File.WriteAllText(Path.Combine("loot", "users.json"), new JavaScriptSerializer().Serialize(Users));
                File.WriteAllText(Path.Combine("loot", "policy.json"), new JavaScriptSerializer().Serialize(Policies));
            }
            catch (System.Runtime.InteropServices.COMException ex)
            {
                switch ((uint)ex.ErrorCode)
                {
                    case 0x8007052E:
                        throw new Exception("[-] Login error when retrieving usernames from dc \"" + domainController + "\"! Bad creds?");
                    case 0x8007203A:          
                        throw new Exception("[-] Error connecting with the dc \"" + domainController + "\"! Make sure that provided /domain or /dc are valid");
                    case 0x80072032:          
                        throw new Exception("[-] Invalid syntax in DN specification! Make sure that /ou is correct");
                    case 0x80072030:          
                        throw new Exception("[-] There is no such object on the server! Make sure that /ou is correct");
                    default:
                        throw ex;
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public static void PrintProperties(object myObj, string header = "", int offset = 0)
        {
            string trail = String.Concat(Enumerable.Repeat(" ", offset));

            if (!string.IsNullOrEmpty(header))
                Console.WriteLine(header);

            foreach (var prop in myObj.GetType().GetProperties())
            {
                try
                {
                    if (!string.IsNullOrEmpty((string)(prop.GetValue(myObj, null))))
                        Console.WriteLine(trail + prop.Name + ": " + prop.GetValue(myObj, null));
                }
                catch (Exception e)
                {
                    Console.WriteLine(trail + prop.Name + ": " + prop.GetValue(myObj, null));
                }
            }

            foreach (var field in myObj.GetType().GetFields())
            {
                try
                {
                    if (!string.IsNullOrEmpty((string)field.GetValue(myObj)))
                        Console.WriteLine(trail + field.Name + ": " + field.GetValue(myObj));
                }
                catch (Exception e)
                {
                    Console.WriteLine(trail + field.Name + ": " + field.GetValue(myObj));
                }
            }
        }
    }
}