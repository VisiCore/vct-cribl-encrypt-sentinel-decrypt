// Deploys the Cribl decrypt workbook as a saved Azure Monitor / Sentinel workbook.
// serializedData is the workbook JSON (built by scripts, see workbooks/README or the
// deploy command); sourceId ties it to the Log Analytics workspace so it shows in the
// Microsoft Sentinel -> Workbooks gallery.

@description('Display name shown in the workbooks gallery.')
param workbookDisplayName string = 'Cribl Decrypt'

@description('Location for the workbook.')
param location string = resourceGroup().location

@description('Resource ID of the Log Analytics workspace (Sentinel) this workbook belongs to.')
param workspaceResourceId string

@description('Serialized workbook JSON (the Notebook/1.0 document as a string).')
param serializedData string

@description('Stable GUID name for the workbook so redeploys update in place.')
param workbookId string = guid(resourceGroup().id, workbookDisplayName)

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    serializedData: serializedData
    category: 'sentinel'
    sourceId: workspaceResourceId
    version: '1.0'
  }
}

output workbookResourceId string = workbook.id
output workbookName string = workbook.name
