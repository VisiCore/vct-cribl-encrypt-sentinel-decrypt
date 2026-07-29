// Sentinel playbook (Logic App, Consumption) — the on-demand decrypt action.
//
// This is the analyst-facing half of the "Option 3" design. An analyst on an
// incident clicks "Run playbook" -> this Logic App reads the Cribl-encrypted
// values carried on the incident's custom details, POSTs them to the Azure
// Function (infra/), and writes the decrypted plaintext back as an incident
// comment. Ciphertext stays at rest in Log Analytics; plaintext is only ever
// materialized on-demand, in the incident comment, for an authorized run.
//
// Contract: the Sentinel analytics rule must surface the encrypted field(s) as a
// custom detail named `CriblEncrypted` (an array of `#keyId:iv:ct#` tokens).
//
// The Function endpoint + function key are passed as ONE secure parameter
// (full URL incl. `?code=...`). For the POC this is the simplest secure wiring;
// hardening note in README covers moving to Easy Auth / managed identity.

@description('Name of the Sentinel playbook (Logic App).')
param playbookName string = 'cribl-decrypt-playbook'

@description('Location for the Logic App. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Full Azure Function endpoint for the decrypt route, including the ?code= function key. e.g. https://<app>.azurewebsites.net/api/decrypt?code=<key>')
@secure()
param functionEndpoint string

@description('Custom-detail key on the incident that carries the array of Cribl tokens.')
param customDetailKey string = 'CriblEncrypted'

@description('Grant the playbook identity "Microsoft Sentinel Responder" at the resource group so it can comment on incidents. Disable if you assign it elsewhere.')
param assignSentinelResponderRole bool = true

// Microsoft Sentinel Responder built-in role.
var sentinelResponder = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ab8e14d6-4a74-4a29-9ba8-549422addade')

// The azuresentinel managed API connection used by both the incident trigger and
// the "add comment" action. Authenticated with the Logic App's managed identity.
resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: '${playbookName}-azuresentinel'
  location: location
  properties: {
    displayName: '${playbookName}-azuresentinel'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
    // 'Alternative' selects the managed-identity auth path for the azuresentinel
    // connector; the workflow then supplies ManagedServiceIdentity in $connections.
    // (The 2016-06-01 type schema predates this property, hence the suppress.)
    #disable-next-line BCP037
    parameterValueType: 'Alternative'
  }
}

resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: playbookName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    state: 'Enabled'
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
            connectionProperties: {
              authentication: { type: 'ManagedServiceIdentity' }
            }
          }
        }
      }
      functionEndpoint: { value: functionEndpoint }
      customDetailKey: { value: customDetailKey }
    }
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': { type: 'Object' }
        functionEndpoint: { type: 'SecureString' }
        customDetailKey: { type: 'String' }
      }
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            body: { callback_url: '@{listCallbackUrl()}' }
            host: {
              connection: { name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']' }
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        // Pull the token array off the incident custom details (default to []).
        Init_encrypted: {
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'encrypted'
                type: 'array'
                value: '@coalesce(triggerBody()?[\'object\']?[\'properties\']?[\'additionalData\']?[\'customDetails\']?[parameters(\'customDetailKey\')], json(\'[]\'))'
              }
            ]
          }
        }
        Has_encrypted_values: {
          type: 'If'
          runAfter: { Init_encrypted: [ 'Succeeded' ] }
          expression: {
            and: [ { greater: [ '@length(variables(\'encrypted\'))', 0 ] } ]
          }
          actions: {
            Call_decrypt_function: {
              type: 'Http'
              inputs: {
                method: 'POST'
                uri: '@parameters(\'functionEndpoint\')'
                headers: { 'Content-Type': 'application/json' }
                body: { values: '@variables(\'encrypted\')' }
              }
            }
            Parse_results: {
              type: 'ParseJson'
              runAfter: { Call_decrypt_function: [ 'Succeeded' ] }
              inputs: {
                content: '@body(\'Call_decrypt_function\')'
                schema: {
                  type: 'object'
                  properties: {
                    results: {
                      type: 'array'
                      items: {
                        type: 'object'
                        properties: {
                          input: { type: 'string' }
                          plaintext: { type: 'string' }
                          ok: { type: 'boolean' }
                          error: { type: 'string' }
                        }
                      }
                    }
                  }
                }
              }
            }
            // Build one HTML row per value: "<code>token</code> -> plaintext|error".
            Format_rows: {
              type: 'Select'
              runAfter: { Parse_results: [ 'Succeeded' ] }
              inputs: {
                from: '@body(\'Parse_results\')?[\'results\']'
                select: '@concat(\'<code>\', item()?[\'input\'], \'</code> &rarr; \', if(equals(item()?[\'ok\'], true), item()?[\'plaintext\'], concat(\'<i>\', coalesce(item()?[\'error\'], \'decrypt_failed\'), \'</i>\')))'
              }
            }
            Add_comment_to_incident: {
              type: 'ApiConnection'
              runAfter: { Format_rows: [ 'Succeeded' ] }
              inputs: {
                host: {
                  connection: { name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']' }
                }
                method: 'post'
                path: '/Incidents/Comment'
                body: {
                  incidentArmId: '@triggerBody()?[\'object\']?[\'id\']'
                  message: '@concat(\'<h3>Cribl decrypt results</h3>\', join(body(\'Format_rows\'), \'<br>\'))'
                }
              }
            }
          }
          else: { actions: {} }
        }
      }
    }
  }
}

// Let the playbook's managed identity comment on incidents in this resource group.
resource responderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (assignSentinelResponderRole) {
  name: guid(resourceGroup().id, playbook.id, sentinelResponder)
  properties: {
    principalId: playbook.identity.principalId
    roleDefinitionId: sentinelResponder
    principalType: 'ServicePrincipal'
  }
}

output playbookName string = playbook.name
output playbookPrincipalId string = playbook.identity.principalId
output sentinelConnectionName string = sentinelConnection.name
