Set-StrictMode -Version 2.0

$script:TradingLabProhibitedMutationRights = [int64](
    [int64][System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [int64][System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [int64][System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [int64][System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [int64][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [int64][System.Security.AccessControl.FileSystemRights]::Delete -bor
    [int64][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [int64][System.Security.AccessControl.FileSystemRights]::TakeOwnership
)

function Get-TradingLabProhibitedMutationRightsMask {
    return [int64]$script:TradingLabProhibitedMutationRights
}

function Get-TradingLabMutationRightsIntersection([int64] $Rights) {
    return [int64]($Rights -band $script:TradingLabProhibitedMutationRights)
}

function Test-TradingLabFileSystemRightsMutation([int64] $Rights) {
    return (Get-TradingLabMutationRightsIntersection $Rights) -ne 0
}

function Get-TradingLabFileSystemRightsClassification([int64] $Rights) {
    $intersection = Get-TradingLabMutationRightsIntersection $Rights
    return [pscustomobject]@{
        rights = $Rights
        rights_hex = '0x' + $Rights.ToString('X')
        prohibited_mutation_mask = [int64]$script:TradingLabProhibitedMutationRights
        prohibited_mutation_mask_hex = '0x' + $script:TradingLabProhibitedMutationRights.ToString('X')
        mutation_intersection = $intersection
        mutation_intersection_hex = '0x' + $intersection.ToString('X')
        modify_equivalent = $intersection -ne 0
        write_capable = $intersection -ne 0
    }
}
