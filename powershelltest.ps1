## Install-Module -Name PSGraphQL -Repository PSGallery -Scope CurrentUser

$client_id = "useclientid"
$client_secret = "usesecretkey"

# The GraphQL query that defines which data you wish to fetch.
$query = '
  query GraphSearch($query: GraphEntityQueryInput, $controlId: ID, $projectId: String!, $first: Int, $after: String, $fetchTotalCount: Boolean!, $quick: Boolean = true, $fetchPublicExposurePaths: Boolean = false, $fetchInternalExposurePaths: Boolean = false, $fetchIssueAnalytics: Boolean = false, $fetchLateralMovement: Boolean = false, $fetchKubernetes: Boolean = false, $fetchCost: Boolean = false, $issueId: ID) {
    graphSearch(
      query: $query
      controlId: $controlId
      projectId: $projectId
      first: $first
      after: $after
      quick: $quick
      issueId: $issueId
    ) {
      totalCount @include(if: $fetchTotalCount)
      maxCountReached @include(if: $fetchTotalCount)
      pageInfo {
        endCursor
        hasNextPage
      }
      nodes {
        entities {
          isRestricted
          ...PathGraphEntityFragment
          userMetadata {
            isInWatchlist
            isIgnored
            note
          }
          technologies {
            id
            icon
          }
          cost(
            filterBy: {timestamp: {inLast: {amount: 30, unit: DurationFilterValueUnitDays}}}
          ) @include(if: $fetchCost) {
            amortized
            blended
            unblended
            netAmortized
            netUnblended
            currencyCode
          }
          publicExposures(first: 10) @include(if: $fetchPublicExposurePaths) {
            nodes {
              ...NetworkExposureFragment
            }
          }
          otherSubscriptionExposures(first: 10) @include(if: $fetchInternalExposurePaths) {
            nodes {
              ...NetworkExposureFragment
            }
          }
          otherVnetExposures(first: 10) @include(if: $fetchInternalExposurePaths) {
            nodes {
              ...NetworkExposureFragment
            }
          }
          lateralMovementPaths(first: 10) @include(if: $fetchLateralMovement) {
            nodes {
              id
              pathEntities {
                entity {
                  ...PathGraphEntityFragment
                }
              }
            }
          }
          kubernetesPaths(first: 10) @include(if: $fetchKubernetes) {
            nodes {
              id
              path {
                ...PathGraphEntityFragment
              }
            }
          }
        }
        aggregateCount
      }
    }
  }
    
      fragment PathGraphEntityFragment on GraphEntity {
    id
    name
    type
    properties
    issueAnalytics: issues(filterBy: {status: [IN_PROGRESS, OPEN]}) @include(if: $fetchIssueAnalytics) {
      highSeverityCount
      criticalSeverityCount
    }
  }
    

      fragment NetworkExposureFragment on NetworkExposure {
    id
    portRange
    sourceIpRange
    destinationIpRange
    path {
      ...PathGraphEntityFragment
    }
    applicationEndpoints {
      ...PathGraphEntityFragment
    }
  }'

# The variables sent along with the above query
$variables = '{
  "quick": false,
  "fetchPublicExposurePaths": true,
  "fetchInternalExposurePaths": false,
  "fetchIssueAnalytics": false,
  "fetchLateralMovement": true,
  "fetchKubernetes": false,
  "fetchCost": false,
  "first": 50,
  "query": {
    "type": [
      "CLOUD_RESOURCE"
    ],
    "select": true
  },
  "projectId": "*",
  "fetchTotalCount": false
}'

function getwizauth($client_id,$client_secret)
{
    $authuri = 'https://auth.app.wiz.io/oauth/token'
    $header = @{
        Headers = @{ 'content-type' = "application/x-www-form-urlencoded" }
    }
    $params = @{
        grant_type  = 'client_credentials'
        client_id   = $client_id
        client_secret = $client_secret
        audience    =  'wiz-api'
    }
    $response = Invoke-RestMethod $authuri -method POST -Headers $header -Body $params
    $access_token = $response.access_token

    $tokenPayload = $access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    $tokobj = $tokenArray | ConvertFrom-Json
    $dc = $tokobj.dc

    return $access_token, $dc
}

function query_wiz_api($token,$query,$variables,$dc)
{
    $headers = @{
        "content-type" = "application/json"
        "Authorization" = "bearer "+$token
    }
    $result = Invoke-GraphQLQuery -Query $query -Variables $variables -Uri https://api.$dc.app.wiz.io/graphql -Headers $headers
    return $result
}

write-host "Getting token"
$token, $dc = getwizauth $client_id $client_secret
write-host "Getting data"
$result = query_wiz_api $token $query $variables $dc
write-host $result.data.graphSearch.nodes.entities # your data is here!

# If paginating on a Graph Query, then use <'quick': false> in the query variables.
# Uncomment the following section to paginate over all the results:
while ($result.data.data.pageInfo.hasNextPage -eq $True) {
    $endcursor = $result.data.data.pageInfo.endCursor
    # quirk to replace from json to ps, paginate, and parse back again
    $variables = $variables | ConvertFrom-Json
    $variables | Add-Member -Type NoteProperty -Name 'after' -Value '' -Force
    $variables.after = $endcursor
    $variables = $variables | ConvertTo-Json
    $result = query_wiz_api $token $query $variables
    write-host $result.data.graphSearch.nodes.entities
}

