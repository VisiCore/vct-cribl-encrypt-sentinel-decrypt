// Cribl decrypt POC — core Azure infra for the on-demand (Option 3) design.
//
// Provisions:
//   - Storage account (required by the Function runtime)
//   - Log Analytics + Application Insights (function telemetry)
//   - Flex Consumption Function App (Python) with a system-assigned identity
//   - Key Vault (RBAC mode) holding one secret per Cribl keyId: cribl-key-<keyId>
//   - Role assignment: Function identity -> "Key Vault Secrets User"
//
// The Logic App playbook (playbook/) calls the Function; the Function pulls the
// matching Cribl key from Key Vault and decrypts. No key material in code or app
// settings.

@description('Base name for resources; keep short (<= 11 chars) for global uniqueness.')
@minLength(3)
@maxLength(11)
param namePrefix string = 'cribldec'

@description('Location for all resources.')
param location string = resourceGroup().location

@description('Object ID of the operator who uploads Cribl keys (gets Key Vault Secrets Officer).')
param keyAdminObjectId string

var suffix = uniqueString(resourceGroup().id)
// Storage names cap at 24 chars: take(<=9) + 'st'(2) + suffix(13) = <=24.
var storageName = toLower('${take(namePrefix, 9)}st${suffix}')
var functionName = '${namePrefix}-func-${suffix}'
var planName = '${namePrefix}-plan'
var kvName = toLower('${namePrefix}kv${suffix}')
var laName = '${namePrefix}-la'
var aiName = '${namePrefix}-ai'

// Built-in role definition IDs
var kvSecretsUser = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var kvSecretsOfficer = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
// Storage Blob Data Owner — required by the Function MSI for identity-based
// AzureWebJobsStorage and the Flex Consumption deployment container.
var storageBlobDataOwner = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b')

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

// Flex Consumption pushes the deployment package into this blob container.
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}
resource deploymentsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'deployments'
}

resource la 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: laName
  location: location
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 30 }
}

resource ai 'Microsoft.Insights/components@2020-02-02' = {
  name: aiName
  location: location
  kind: 'web'
  properties: { Application_Type: 'web', WorkspaceResourceId: la.id }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  sku: { name: 'FC1', tier: 'FlexConsumption' }
  kind: 'functionapp'
  properties: { reserved: true }
}

resource func 'Microsoft.Web/sites@2023-12-01' = {
  name: functionName
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    functionAppConfig: {
      runtime: { name: 'python', version: '3.11' }
      scaleAndConcurrency: { maximumInstanceCount: 40, instanceMemoryMB: 2048 }
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}deployments'
          authentication: { type: 'SystemAssignedIdentity' }
        }
      }
    }
    siteConfig: {
      appSettings: [
        { name: 'AzureWebJobsStorage__accountName', value: storage.name }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: ai.properties.ConnectionString }
        { name: 'KEY_VAULT_URI', value: kv.properties.vaultUri }
      ]
    }
  }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
  }
}

// Function identity needs blob access for AzureWebJobsStorage + deployment container
resource funcStorageRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, func.id, storageBlobDataOwner)
  scope: storage
  properties: {
    principalId: func.identity.principalId
    roleDefinitionId: storageBlobDataOwner
    principalType: 'ServicePrincipal'
  }
}

// Function identity may READ secrets
resource funcKvRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, func.id, kvSecretsUser)
  scope: kv
  properties: {
    principalId: func.identity.principalId
    roleDefinitionId: kvSecretsUser
    principalType: 'ServicePrincipal'
  }
}

// Operator may WRITE secrets (upload Cribl keys)
resource adminKvRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, keyAdminObjectId, kvSecretsOfficer)
  scope: kv
  properties: {
    principalId: keyAdminObjectId
    roleDefinitionId: kvSecretsOfficer
    principalType: 'User'
  }
}

output functionAppName string = func.name
output functionDefaultHostName string = func.properties.defaultHostName
output keyVaultName string = kv.name
output keyVaultUri string = kv.properties.vaultUri
