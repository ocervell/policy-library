#
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package templates.gcp.GCPEnforceLabelConstraintV1

import data.validator.gcp.lib as lib

deny[{
 "msg": message,
 "details": metadata,
}] {
  constraint := input.constraint
  asset := input.asset
  asset.asset_type == "cloudresourcemanager.googleapis.com/Project"

  allowed_billing_accounts := lib.get_default(params, "allowed_billing_accounts", [])
  billing_account =

  count({billing_account} & cast_set(allowed_billing_accounts)) == 0

  message := sprintf("%v\'s billing account is invalid.", [asset.name])
  metadata := {
    "resource": asset.name,
    "billing_account": billing_account,
    "allowed_billing_accounts": allowed_billing_accounts
  }
}

# get_billing_account for GCP projects
get_billing_account(asset, non_standard_types) = resource_labels {
 # check if we have a non-standard type
 asset.asset_type == non_standard_types[_]
 asset.asset_type == "sqladmin.googleapis.com/Instance"
 resource := asset.resource.data.settings
 resource_labels := lib.get_default(resource, "userLabels", {})
}
