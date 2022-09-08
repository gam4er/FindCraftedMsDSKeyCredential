using DSInternals.Common.Data;
using Spectre.Console;
using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
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

        private static void WriteLogMessage(string message)
        {
            AnsiConsole.MarkupLine($"[bold grey]LOG:[/] {message}");
        }

        private static void WriteErrorMessage(string message)
        {
            AnsiConsole.MarkupLine($"[bold red]ERROR:[/] {message}");
        }

        private static void WriteWarningMessage(string message)
        {
            AnsiConsole.MarkupLine($"[bold gold1]Warning:[/] {message}");
        }

        private static void WriteFindMessage(string message)
        {
            AnsiConsole.MarkupLine($"[bold yellow]{message} [/]");
        }

        private static Table CreateTable(string sid, DirectoryEntry DE, KeyCredential kc)
        {
            /*
            WriteFindMessage(String.Format("Distinguished Name: {0}", DE.Properties["distinguishedName"][0].ToString()));
            WriteFindMessage(String.Format("DeviceID: {0} | Creation Time: {1}", kc.DeviceId, kc.CreationTime));
            WriteFindMessage(String.Format("Length of key: {0} | Flags: {1}", kc.RawKeyMaterial.Length, kc.CustomKeyInfo.Flags));
            */

            return new Table()
                .Border(TableBorder.HeavyEdge)
                .BorderColor(Color.BlueViolet)
                .Title(String.Format("[magenta2]Listing msDS-KeyCredentialLink entry for {0}[/]", sid))
                //.Caption("TABLE [yellow]CAPTION[/]")
                .AddColumn("Key")
                .AddColumn("Value")
                .AddRow(new Text("Distinguished Name").LeftAligned(), new Markup(String.Format("[green]{0}[/]", DE.Properties["distinguishedName"][0].ToString())))
                .AddRow(new Text("DeviceID").LeftAligned(), new Markup(String.Format("[green]{0}[/]", kc.DeviceId)))
                .AddRow(new Text("Creation Time").LeftAligned(), new Markup(String.Format("[green]{0}[/]", kc.CreationTime)))
                .AddRow(new Text("Length of key").LeftAligned(), new Markup(String.Format("[green]{0}[/]", kc.RawKeyMaterial.Length)))
                .AddRow(new Text("Owner (from binary part)").LeftAligned(), new Markup(String.Format("[green]{0}[/]", kc.Owner)))
                .AddRow(new Text("Flags").LeftAligned(), new Markup(String.Format("[green]{0}[/]", kc.CustomKeyInfo.Flags)));

        }

        private static int DoesIHaveReadAcces(DirectoryEntry DE)
        {
            string sid = new SecurityIdentifier((byte[])DE.Properties["objectSid"][0], 0).ToString();
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
                                WriteWarningMessage(String.Format("Current user [bold green]{0}[/] is in role of {1}", System.Security.Principal.WindowsIdentity.GetCurrent().Name, ntAccount.Value));
                                WriteWarningMessage(String.Format("That [bold green]has ALLOWED[/] read access to [bold green]{0}[/]", sid));
                                //Console.WriteLine("Current user is in role of {0}, that has read access", ntAccount.Value);
                                //continue;
                                //break;
                                return 1;
                            }
                            else
                            {
                                WriteWarningMessage(String.Format("Current user [bold red]{0}[/] is in role of {1}", System.Security.Principal.WindowsIdentity.GetCurrent().Name, ntAccount.Value));
                                WriteWarningMessage(String.Format("That [bold red]has DENIED[/] read access to [bold red]{0}[/]", sid));
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
                //WriteErrorMessage(String.Format("Current user does not have any access to {0}", DE.Path));
                WriteErrorMessage(String.Format("Current user [bold red]{0}[/] does not have any access to [bold red]{1}[/]", System.Security.Principal.WindowsIdentity.GetCurrent().Name, sid));
                return -1;
            }
            catch
            {
                WriteErrorMessage(String.Format("Unhandled exception while check access to [bold red]{0}[/]", sid));
                //Console.WriteLine("Unhandled exception while check access to {0}", DE.Path);
            }
            return -2;
        }

        public static void FindMsDSKeyCredentialWithDeviceID(DirectoryEntry objADAM, StatusContext ctx)
        {
            WriteLogMessage(String.Format("Searching msDS-KeyCredentialLink for: {0}", objADAM.Path));
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
            ctx.Status($"[bold blue]Objects with msDS-KeyCredentialLink attribute processed: {count}[/]");

            var iter = objSearchResults.GetEnumerator();
            using (iter as IDisposable)
            {
                try
                {
                    while (iter.MoveNext())
                    {
                        ctx.Spinner(Spinner.Known.Ascii);
                        ctx.Status($"[bold blue]Objects with msDS-KeyCredentialLink attribute processed: {count}[/]");

                        DirectoryEntry DE = ((SearchResult)iter.Current).GetDirectoryEntry();
                        string sid = String.Empty;
                        sid = new SecurityIdentifier((byte[])DE.Properties["objectSid"][0], 0).ToString();

                        DoesIHaveReadAcces(DE);

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
                                        AnsiConsole.Write(CreateTable(sid, DE, kc));
                                    }
                                }
                                catch (NullReferenceException ex)
                                {
                                    WriteErrorMessage(String.Format("Key bytes is null for user {0}", DE.Name));
                                    WriteErrorMessage(String.Format("Message: {0}", ex.Message));
                                }
                                catch (Exception ex)
                                {
                                    WriteErrorMessage(String.Format("Cannot convert key bytes to msDS-KeyCredentialLink structure for user {0}", DE.Name));
                                    WriteErrorMessage(String.Format("Message: {0}", ex.Message));
                                }
                            }
                        }
                        count++;
                    }
                }
                catch (DirectoryServicesCOMException ex)
                {
                    WriteErrorMessage(String.Format("Some COM error {0}", ex.Data));
                    WriteErrorMessage(String.Format("Exception code {0}", ex.ErrorCode));
                    WriteErrorMessage(String.Format("Exception extended code {0}", ex.ExtendedError));
                    WriteErrorMessage(String.Format("Exception extended message code {0}", ex.ExtendedErrorMessage));
                }
            }

        }

        static void Main(string[] args)
        {

            //AnsiConsole.Write(CreateTable());

            Forest Forest = Forest.GetForest(new DirectoryContext(DirectoryContextType.Forest));
            DomainCollection AllDomains = Forest.Domains;
            DirectoryEntry entry = AllDomains[0].GetDirectoryEntry();

            AnsiConsole.Record();

            AnsiConsole.Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.Default)
                .Start(String.Format("[yellow]Searching for suspicious msDS-KeyCredentialLink for: {0} Forest[/]", Forest.Name), ctx =>
                {
                    WriteLogMessage(String.Format("[yellow]Searching for suspicious msDS-KeyCredentialLink for: {0} Forest[/]", Forest.Name));
                    foreach (Domain domain in AllDomains)
                        FindMsDSKeyCredentialWithDeviceID(domain.GetDirectoryEntry(), ctx);
                });
            File.WriteAllText("output.html", AnsiConsole.ExportHtml());
        }
    }
}
