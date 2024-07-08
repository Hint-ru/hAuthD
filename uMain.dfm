object frmMain: TfrmMain
  Left = 587
  Top = 166
  Width = 550
  Height = 348
  Caption = 'hAuthD'
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  Menu = MainMenu
  OldCreateOrder = False
  Position = poScreenCenter
  OnCloseQuery = FormCloseQuery
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object reLog: TRichEdit
    Left = 0
    Top = 0
    Width = 534
    Height = 271
    Align = alClient
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'MS Sans Serif'
    Font.Style = [fsBold]
    HideScrollBars = False
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 0
    WordWrap = False
  end
  object sb: TStatusBar
    Left = 0
    Top = 271
    Width = 534
    Height = 18
    Panels = <
      item
        Text = 'Uptime: ? d ?? h ?? m'
        Width = 130
      end
      item
        Text = 'Servers: 0'
        Width = 90
      end
      item
        Text = 'Users: 0'
        Width = 90
      end
      item
        Text = 'Cheats: 0'
        Width = 90
      end
      item
        Text = 'Served: 0'
        Width = 90
      end
      item
        Width = 50
      end>
  end
  object XPManifest: TXPManifest
    Left = 440
    Top = 24
  end
  object MainMenu: TMainMenu
    Left = 400
    Top = 24
    object miServerGroup: TMenuItem
      Caption = '&Server'
      object miServer: TMenuItem
        Caption = 'Enable'
        Enabled = False
        OnClick = miServerClick
      end
      object miReloadWorlds: TMenuItem
        Caption = 'Reload worlds'
        Enabled = False
        OnClick = miReloadWorldsClick
      end
      object N5: TMenuItem
        Caption = '-'
      end
      object miOptions: TMenuItem
        Caption = 'Options'
        OnClick = miOptionsClick
        object miTestMode: TMenuItem
          Caption = 'Test Mode'
          OnClick = miTestModeClick
        end
      end
    end
    object Options1: TMenuItem
      Caption = '&Files'
      OnClick = Options1Click
      object Reload: TMenuItem
        Caption = '&Reload'
        OnClick = ReloadClick
      end
      object N1: TMenuItem
        Caption = '-'
      end
      object Workingdirectory1: TMenuItem
        Caption = 'Working directory'
        OnClick = Workingdirectory1Click
      end
      object N6: TMenuItem
        Caption = '-'
      end
      object opt_black_ips: TMenuItem
        Caption = 'Black IPs'
        OnClick = opt_black_ipsClick
      end
      object opt_black_hkeys: TMenuItem
        Caption = 'Black hKeys'
        OnClick = opt_black_hkeysClick
      end
      object opt_white_ids: TMenuItem
        Caption = 'White IDs'
        OnClick = opt_white_idsClick
      end
      object miTestIDs: TMenuItem
        Caption = 'Test IDs'
        OnClick = miTestIDsClick
      end
      object mi_Hot: TMenuItem
        Caption = '-'
      end
      object mi_hot_hkeys: TMenuItem
        Caption = 'Hot hKeys'
        OnClick = mi_hot_hkeysClick
      end
      object mi_hot_ids: TMenuItem
        Caption = 'Hot IDs'
        OnClick = mi_hot_idsClick
      end
    end
    object miCheaters: TMenuItem
      Caption = 'Cheaters'
      object miShow: TMenuItem
        Caption = 'Show list'
        OnClick = miShowClick
      end
      object miBlock: TMenuItem
        Caption = 'Block all'
        OnClick = miBlockClick
      end
      object N3: TMenuItem
        Caption = '-'
      end
      object Forgiveall1: TMenuItem
        Caption = 'Forgive all'
        OnClick = Forgiveall1Click
      end
    end
    object Log1: TMenuItem
      Caption = '&Log'
      object mi_LAuth: TMenuItem
        Caption = '&Open '#39'&Auth'#39
        OnClick = mi_LAuthClick
      end
      object mi_LGuard: TMenuItem
        Caption = 'Open '#39'&Guard'#39
        OnClick = mi_LGuardClick
      end
      object mi_LAll: TMenuItem
        Caption = 'Open '#39'All'#39
        OnClick = mi_LAllClick
      end
      object N2: TMenuItem
        Caption = '-'
      end
      object mi_Debug: TMenuItem
        Caption = 'Debug'
        OnClick = mi_DebugClick
      end
      object N4: TMenuItem
        Caption = '-'
      end
      object Clear1: TMenuItem
        Caption = '&Clear'
        OnClick = Clear1Click
      end
    end
    object Homepage1: TMenuItem
      Caption = 'Help'
      object Homepage2: TMenuItem
        Caption = 'Homepage'
        OnClick = Homepage2Click
      end
    end
  end
  object ADOConnection: TADOConnection
    CommandTimeout = 5
    ConnectionTimeout = 5
    Provider = 
      'C:\Program Files\Common Files\System\OLE DB\Data Links\lin2db.ud' +
      'l'
    Left = 176
    Top = 48
  end
  object ADO: TADODataSet
    Connection = ADOConnection
    CommandTimeout = 5
    Parameters = <>
    Left = 208
    Top = 48
  end
end
