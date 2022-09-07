using DSInternals.Common.Data;
using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;

namespace FindCraftedMsDSKeyCredential
{
    internal class Program
    {
        private static void DecodeDnWithBinary(object dnWithBinary, out byte[] binaryPart, out string dnString)
        {
            System.Type type = dnWithBinary.GetType();

            binaryPart = (byte[])type.InvokeMember(
            "BinaryValue",
            BindingFlags.GetProperty,
            null,
            dnWithBinary,
            null
            );

            dnString = (string)type.InvokeMember(
            "DNString",
            BindingFlags.GetProperty,
            null,
            dnWithBinary,
            null
            );
        }

        private static int DoesIHaveReadAcces(DirectoryEntry DE)
        {
            try
            {
                AuthorizationRuleCollection rules = DE.ObjectSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

                WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(currentUser);
                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    if ((rule.ActiveDirectoryRights &
                        (
                            ActiveDirectoryRights.GenericRead |
                            ActiveDirectoryRights.GenericExecute |
                            ActiveDirectoryRights.ReadProperty
                        )) > 0)
                    {
                        NTAccount ntAccount = rule.IdentityReference as NTAccount;
                        if (ntAccount == null)
                        {
                            continue;
                        }

                        if (principal.IsInRole(ntAccount.Value))
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                            {
                                Console.WriteLine("Current user is in role of {0}, that has read access", ntAccount.Value);
                                //continue;
                                //break;
                                return 1;
                            }
                            else
                            {
                                Console.WriteLine("Current user is in role of {0}, that has DENIED read access", ntAccount.Value);
                                //continue;
                                //break;
                                return 0;
                            }
                        }
                        //Console.WriteLine("Current user is not in role of {0}, does not have write access", ntAccount.Value);
                    }
                }
                return 2;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Current user does not have any access to {0}", DE.Path);
                return -1;
            }
            catch
            {
                Console.WriteLine("Unhandled exception while check access to {0}", DE.Path);
            }
            return -2;
        }

        public static void FindMsDSKeyCredentialWithDeviceID(DirectoryEntry objADAM)
        {
            Console.WriteLine("\n[*] Searching msDS-KeyCredentialLink with deviced for: {0}", objADAM.Path);
            DirectorySearcher objSearchADAM = new DirectorySearcher(objADAM);
            objSearchADAM.Filter = "(msDS-KeyCredentialLink=*)"; 
            objSearchADAM.SearchScope = SearchScope.Subtree;            
            //objSearchADAM.Sort.PropertyName = "cn";
            //objSearchADAM.Sort.Direction = SortDirection.Ascending;
            objSearchADAM.CacheResults = false;
            objSearchADAM.PageSize = 5000;
            objSearchADAM.SizeLimit = 50000;
            objSearchADAM.ServerTimeLimit = new TimeSpan(0, 1, 0, 0);
            //objSearchADAM.Asynchronous = false;
            //objSearchADAM.ServerPageTimeLimit = new TimeSpan(1, 0, 0, 0);
            //objSearchADAM.PropertiesToLoad.Add("distinguishedName");
            //objSearchADAM.PropertiesToLoad.Add("objectSid");
            //objSearchADAM.PropertiesToLoad.Add("msDS-KeyCredentialLink");

            SearchResultCollection objSearchResults = objSearchADAM.FindAll();

            int count = 0;

            var iter = objSearchResults.GetEnumerator();
            using (iter as IDisposable)
            {
                try
                {
                    while (iter.MoveNext())
                    {
                        //var user = (MemberUser)iter.Current;
                        //DirectoryEntry DE = SR.GetDirectoryEntry();
                        DirectoryEntry DE = ((SearchResult) iter.Current).GetDirectoryEntry(); 
                        string sid = String.Empty;
                        sid = new SecurityIdentifier((byte[])DE.Properties["objectSid"][0], 0).ToString();

                        
                        Console.Write("\x000DUsers with attribute processed: " + count);

                        if (DE.Properties["msDS-KeyCredentialLink"].Count == 0)
                            Console.WriteLine("[*] No entries!");
                        else
                        {
                            for (int i = 0; i < DE.Properties["msDS-KeyCredentialLink"].Count; i++)
                            {
                                byte[] binaryPart = null;
                                string dnString = null;
                                DecodeDnWithBinary(DE.Properties["msDS-KeyCredentialLink"][i], out binaryPart, out dnString);
                                /*
                                 * 0x01 - DES-CBC-CRC
                                 * 0x02 - DES-CBC-MD5
                                 * 0x04 - RC4-HMAC
                                 */
                                //int SupportedEncryptionTypes = (int)DE.Properties["msDS-SupportedEncryptionTypes"][0];
                                try
                                {
                                    KeyCredential kc = new KeyCredential(binaryPart, dnString);

                                    if
                                        (
                                        kc.DeviceId.HasValue ||
                                        kc.CustomKeyInfo.Flags != KeyFlags.MFANotUsed ||
                                        kc.RawKeyMaterial.Length != 270 ||
                                        !kc.Owner.Contains(DE.Name)
                                        )
                                    {
                                        Console.WriteLine();
                                        Console.WriteLine("[*] Listing suspicious deviceID for {0}:", sid);
                                        Console.WriteLine("Distinguished Name: {0}", DE.Properties["distinguishedName"][0].ToString());                                        
                                        Console.WriteLine("DeviceID: {0} | Creation Time: {1}", kc.DeviceId, kc.CreationTime);
                                        Console.WriteLine("Length of key: {0} | Flags: {1}", kc.RawKeyMaterial.Length, kc.CustomKeyInfo.Flags);
                                        //Console.WriteLine("Alarm");
                                    }
                                }
                                catch (NullReferenceException)
                                {
                                    Console.WriteLine("\nKey bytes is null for user {0}", DE.Name);
                                }
                                catch (Exception)
                                {
                                    Console.WriteLine("Cannot convert key bytes to msDS-KeyCredentialLink structure for user {0}", DE.Name);
                                }
                            }
                        }
                        count++;
                    }
                }
                catch(DirectoryServicesCOMException ex)
                {
                    Console.WriteLine("Some COM error {0}", ex.Data);
                    Console.WriteLine("Exception code {0}", ex.ErrorCode);
                    Console.WriteLine("Exception extended code {0}", ex.ExtendedError);
                    Console.WriteLine("Exception extended message code {0}", ex.ExtendedErrorMessage);
                }
            }

        }

        static void Main(string[] args)
        {

            Forest Forest = Forest.GetForest(new DirectoryContext(DirectoryContextType.Forest)) ;
            DomainCollection AllDomains = Forest.Domains;

            DirectoryEntry entry = AllDomains[0].GetDirectoryEntry();

            foreach (Domain domain in AllDomains)
                FindMsDSKeyCredentialWithDeviceID(domain.GetDirectoryEntry());
        }
    }
}
