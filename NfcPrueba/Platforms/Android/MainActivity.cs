using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Nfc;
using Android.Nfc.Tech;
using Android.OS;
using Plugin.NFC;
using System.Text;

namespace NfcPrueba
{
	[Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true, ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
	[IntentFilter(new[] { NfcAdapter.ActionNdefDiscovered }, Categories = new[] { Intent.CategoryDefault }, DataMimeType = "application/com.companyname.yourapp")]
	public class MainActivity : MauiAppCompatActivity
	{
		protected override void OnCreate(Bundle savedInstanceState)
		{
			// Plugin NFC : Initialisation
			CrossNFC.Init(this);

			base.OnCreate(savedInstanceState);
		}
		protected override void OnResume()
		{
			base.OnResume();

			// Plugin NFC: Restart NFC listening on resume (needed for Android 10+) 
			CrossNFC.OnResume();
		}
		protected override void OnNewIntent(Android.Content.Intent intent)
		{
			base.OnNewIntent(intent);

			// Pass the NFC intent to the Plugin.NFC library
			//CrossNFC.OnNewIntent(intent);

			// Handle the NFC tag using Android NFC APIs
			Android.Nfc.Tag androidTag = intent.GetParcelableExtra(NfcAdapter.ExtraTag) as Android.Nfc.Tag;
            if (androidTag != null)
            {
                // Identify the tag and try to read data
                string result = IdentifyTag(androidTag);
                Console.WriteLine(result);
            }
            if (androidTag != null)
			{
				string result = ReadMifareClassicData(androidTag);
				// Display or process the result
				Console.WriteLine(result);
			}
		}
        private string IdentifyTag(Android.Nfc.Tag androidTag)
        {
            // Get the tag ID (optional, for logging)
            byte[] tagId = androidTag.GetId();
            string tagIdStr = BitConverter.ToString(tagId);
            Console.WriteLine($"Tag ID: {tagIdStr}");

            // List all tag technologies
            string[] techList = androidTag.GetTechList();
            Console.WriteLine("Technologies supported by this tag:");

            foreach (string tech in techList)
            {
                Console.WriteLine(tech);
            }

            // Check if MifareClassic is supported
            if (techList.Contains("android.nfc.tech.MifareClassic"))
            {
                return ReadMifareClassicData(androidTag);
            }
            if (techList.Contains("android.nfc.tech.NfcV"))
            {
                Console.WriteLine("nfcv");
                Console.WriteLine(GetSystemInfo(NfcV.Get(androidTag)));
                return ReadNfcVTagData(androidTag);
            }

            return "Tag is not a Mifare Classic tag. Supported technologies: " + string.Join(", ", techList);
        }
        private (int totalBlocks, int blockSize) GetSystemInfo(NfcV nfcV)
        {
            try
            {
                // Command for Get System Information
                byte[] command = new byte[] {
            0x00, // Flags
            0x2B  // Command (Get System Information)
        };

                // Send the command and receive the response
                byte[] response = nfcV.Transceive(command);

                // Extract memory information from the response
                // This depends on the tag, often the last two bytes indicate memory size and block size
                int totalBlocks = response[10];  // Assuming totalBlocks is stored in byte 10
                int blockSize = response[11];    // Assuming blockSize is stored in byte 11

                return (totalBlocks, blockSize);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving system info: {ex.Message}");
                return (0, 0);
            }
        }
        private string ReadNfcVTagData(Android.Nfc.Tag androidTag)
        {
            var nfcV = NfcV.Get(androidTag);
            if (nfcV != null)
            {
                string blockData = "";
                try
                {
                    nfcV.Connect();
                    for (int i = 0; i <= 0xff; i++)
                    {
                        // Example: Read the first block of data (you can adjust this based on your tag’s structure)
                        byte[] command = new byte[] {
                0x00, // Flags
                0x20, // Command (Read Single Block)
                (byte)i  // Block number (e.g., 0 for the first block)
            };

                        // Send the command and read data from block 0
                        byte[] response = nfcV.Transceive(command);

                        // Convert the byte array to a string (for demonstration purposes)
                        blockData = BitConverter.ToString(response);
                        Console.WriteLine($"Block {i} Data: {blockData}");
                    }
                    return $"Block 0 Data: {blockData}";
                }
                catch (Exception ex)
                {
                    return $"Error: {ex.Message}";
                }
                finally
                {
                    nfcV.Close();
                }
            }

            return "Failed to read NfcV tag.";
        }
        private string ReadMifareClassicData(Android.Nfc.Tag androidTag)
		{
			var mifareClassic = MifareClassic.Get(androidTag);
			if (mifareClassic != null)
            {
                List<byte[]> datas = new List<byte[]>();
                try
				{
					mifareClassic.Connect();

					// Authenticate with the default key (you can change this as needed)
					bool authenticated = mifareClassic.AuthenticateSectorWithKeyA(0, MifareClassic.KeyDefault.ToArray());

					if (authenticated)
						for (int i = 0; i < 5; i++)
						{
							Console.WriteLine(i);
							// Read the first block of data (as an example)
							byte[] data = mifareClassic.ReadBlock(i);
							datas.Append(data);
							
							Console.WriteLine(Encoding.UTF8.GetString(data));
						}
					else return "Failed to authenticate.";

					return datas.ToString();
				}
				catch (Exception ex)
				{
					return $"Error: {ex.Message}";
				}
				finally
				{
					mifareClassic.Close();
				}
			}

			return "Tag is not a Mifare Classic tag.";
		}
	}
}


