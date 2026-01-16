#!/usr/bin/env sh
#
# deploy/f5.sh -- acme.sh deploy hook for F5 BIG-IP (iControl REST)
#
# Usage from acme.sh:
#   export DEPLOY_F5_HOST="bigip.example.net"
#   export DEPLOY_F5_USER="admin"
#   export DEPLOY_F5_PW="hunter2"
#   export DEPLOY_F5_NAME="example.com"           # optional (defaults to domain)
#   export DEPLOY_F5_PARTITION="Common"           # optional
#   export HTTPS_INSECURE="true"                  # optional: set to "true"/"1"/"yes" to skip TLS verification
#   export DEPLOY_F5_CLIENT_SSL="profile1,profile2" # optional: client-ssl profiles to update/create
#   acme.sh --deploy -d example.com --deploy-hook f5
#
# Returns 0 on success, non-zero on error.

_f5_log() {
  if command -v _info >/dev/null 2>&1 && command -v _err >/dev/null 2>&1; then
    [ "$1" = "err" ] && shift && _err "$@" || _info "$@"
  else
    case "$1" in
      err) shift; printf "ERROR: %s\n" "$*" >&2 ;;
      debug) shift; [ "${DEPLOY_F5_DEBUG:-0}" != "0" ] && printf "DEBUG: %s\n" "$*" ;;
      *) printf "%s\n" "$*" ;;
    esac
  fi
}

# Helper: http call with optional token or basic auth
_f5_curl() {
  if [ -n "${DEPLOY_F5_TOKEN:-}" ]; then
    curl ${DEPLOY_F5_CURL_FLAGS:-"-sS"} -H "X-F5-Auth-Token: ${DEPLOY_F5_TOKEN}" "$@"
  else
    curl ${DEPLOY_F5_CURL_FLAGS:-"-sS"} -u "${DEPLOY_F5_USER}:${DEPLOY_F5_PW}" "$@"
  fi
}

# Upload a local file to Big-IP upload area (/var/config/rest/downloads/<remote>)
# args: local_file remote_filename host insecure_flag
_f5_upload_file() {
  local local_file="$1"
  local remote_name="$2"
  local host="$3"
  local insecure_flag="$4"

  if [ ! -f "$local_file" ]; then
    _f5_log err "local file not found: $local_file"
    return 2
  fi

  local size
  size=$(wc -c <"$local_file" 2>/dev/null | tr -d ' ') || size=$(stat -c%s "$local_file" 2>/dev/null || stat -f%z "$local_file" 2>/dev/null)
  if [ -z "$size" ] || [ "$size" -eq 0 ]; then
    _f5_log err "cannot determine size of $local_file"
    return 3
  fi

  local range="0-$((size - 1))/$size"
  _f5_log "Uploading '$local_file' -> https://$host/mgmt/shared/file-transfer/uploads/$remote_name (size=$size)"

  local curl_insecure=""
  [ "${insecure_flag}" = "true" ] && curl_insecure="-k"

  _f5_curl ${curl_insecure} -X POST \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Range: ${range}" \
    --data-binary @"${local_file}" \
    "https://${host}/mgmt/shared/file-transfer/uploads/${remote_name}"

  return $?
}

# Install a cert/key on the Big-IP from uploaded file
# F5 will automatically append .crt or .key to the object name
# args: host obj_type remote_name obj_name insecure_flag
_f5_install_object() {
  local host="$1"
  local obj_type="$2"   # cert or key
  local remote_name="$3" # filename in uploads
  local obj_name="$4"    # name to create in BIG-IP (F5 adds .crt/.key automatically)
  local insecure_flag="$5"

  local api_path
  if [ "$obj_type" = "cert" ]; then
    api_path="/mgmt/tm/sys/crypto/cert"
  else
    api_path="/mgmt/tm/sys/crypto/key"
  fi

  local payload
  payload=$(printf '{"command":"install","name":"%s","from-local-file":"/var/config/rest/downloads/%s"}' "$obj_name" "$remote_name")

  _f5_log "Installing $obj_type as '$obj_name' from '/var/config/rest/downloads/$remote_name'"

  local curl_insecure=""
  [ "${insecure_flag}" = "true" ] && curl_insecure="-k"

  local result
  result=$(_f5_curl ${curl_insecure} -H "Content-Type: application/json" -X POST -d "${payload}" "https://${host}${api_path}" 2>&1)
  local rc=$?

  _f5_log debug "Install result: $result"
  return $rc
}

# Patch or create a client-ssl profile to reference cert/key (and use cert as chain too)
_f5_update_client_ssl() {
  local host="$1"
  local partition="$2"
  local profiles_csv="$3"
  local certname="$4"    # base name (without .crt/.key extension)
  local keyname="$5"     # base name (without .crt/.key extension)
  local insecure_flag="$6"

  local curl_insecure=""
  [ "${insecure_flag}" = "true" ] && curl_insecure="-k"

  local p
  for p in $(echo "$profiles_csv" | sed 's/,/ /g'); do
    [ -z "$p" ] && continue

    local encoded="~${partition}~${p}"
    local uri="https://${host}/mgmt/tm/ltm/profile/client-ssl/${encoded}"

    _f5_log "Updating client-ssl profile '$p' -> cert=/${partition}/${certname}, chain=/${partition}/${certname}, key=/${partition}/${keyname}"

    # Check if profile exists
    local check_status
    check_status=$(_f5_curl ${curl_insecure} -o /dev/null -w "%{http_code}" -X GET "${uri}" 2>/dev/null || echo "000")

    if [ "$check_status" = "200" ]; then
      # Profile exists -> PATCH with certKeyChain including chain (same cert)
      local patch_body
      patch_body=$(printf '{"certKeyChain":[{"name":"default","cert":"/%s/%s","chain":"/%s/%s","key":"/%s/%s"}]}' \
        "$partition" "$certname" "$partition" "$certname" "$partition" "$keyname")

      _f5_log debug "PATCH body: $patch_body"
      _f5_log debug "PATCH URI: $uri"

      local patch_result patch_status
      patch_result=$(_f5_curl ${curl_insecure} -w "\n%{http_code}" -X PATCH \
        -H "Content-Type: application/json" \
        -d "${patch_body}" \
        "${uri}" 2>&1)
      patch_status=$(echo "$patch_result" | tail -n1)
      local patch_response
      patch_response=$(echo "$patch_result" | sed '$d')

      if [ "$patch_status" = "200" ] || [ "$patch_status" = "204" ]; then
        _f5_log "Successfully updated profile '$p'"
      else
        _f5_log err "PATCH returned HTTP $patch_status for profile '$p'"
        _f5_log err "Response: $patch_response"
      fi

    elif [ "$check_status" = "404" ]; then
      # Profile does not exist -> create with POST, include chain same as cert
      _f5_log "Profile '$p' not found (HTTP 404) -> creating it"

      local create_uri="https://${host}/mgmt/tm/ltm/profile/client-ssl"
      local create_body
      create_body=$(printf '{"name":"%s","partition":"%s","certKeyChain":[{"name":"default","cert":"/%s/%s","chain":"/%s/%s","key":"/%s/%s"}]}' \
        "$p" "$partition" "$partition" "$certname" "$partition" "$certname" "$partition" "$keyname")

      _f5_log debug "POST body: $create_body"

      local create_result create_status
      create_result=$(_f5_curl ${curl_insecure} -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "${create_body}" \
        "${create_uri}" 2>&1)
      create_status=$(echo "$create_result" | tail -n1)
      local create_response
      create_response=$(echo "$create_result" | sed '$d')

      if [ "$create_status" = "200" ] || [ "$create_status" = "201" ]; then
        _f5_log "Successfully created profile '$p'"
      else
        _f5_log err "POST returned HTTP $create_status for profile '$p'"
        _f5_log err "Response: $create_response"
      fi
    else
      _f5_log err "Unexpected HTTP $check_status when checking profile '$p'"
    fi
  done
}

# Main function called by acme.sh
f5_deploy() {
  _domain="$1"
  _ckey="$2"
  _ccert="$3"
  _cca="$4"
  _cfull="$5"

  # Environment / configuration
  DEPLOY_F5_HOST="${DEPLOY_F5_HOST:-${F5_HOST:-}}"
  DEPLOY_F5_USER="${DEPLOY_F5_USER:-${F5_USER:-}}"
  DEPLOY_F5_PW="${DEPLOY_F5_PW:-${F5_PASS:-}}"
  DEPLOY_F5_NAME="${DEPLOY_F5_NAME:-${_domain}}"
  DEPLOY_F5_PARTITION="${DEPLOY_F5_PARTITION:-Common}"
  DEPLOY_F5_CLIENT_SSL="${DEPLOY_F5_CLIENT_SSL:-}"

  # Use HTTPS_INSECURE (acme.sh standard). Accept truthy values: 1|true|yes (case-insensitive)
  _raw_insecure="${HTTPS_INSECURE:-}"
  case "${_raw_insecure}" in
    1|true|TRUE|yes|YES) insecure_flag="true" ;;
    *) insecure_flag="false" ;;
  esac

  if [ -z "$DEPLOY_F5_HOST" ]; then
    _f5_log err "DEPLOY_F5_HOST (F5 address) is required"
    return 1
  fi
  if [ -z "${DEPLOY_F5_TOKEN:-}" ] && ([ -z "$DEPLOY_F5_USER" ] || [ -z "$DEPLOY_F5_PW" ]); then
    _f5_log err "Either DEPLOY_F5_TOKEN or DEPLOY_F5_USER+DEPLOY_F5_PW must be set"
    return 1
  fi

  host="$DEPLOY_F5_HOST"
  partition="$DEPLOY_F5_PARTITION"
  name="$DEPLOY_F5_NAME"

  # Remote filenames for upload (we use .crt/.key extensions for clarity in upload area)
  remote_crt="${name}.crt"
  remote_key="${name}.key"

  # Determine which cert file to upload (prefer fullchain)
  local upload_cert_src
  if [ -n "$_cfull" ] && [ -f "$_cfull" ]; then
    upload_cert_src="$_cfull"
  else
    upload_cert_src="$_ccert"
  fi

  # 1. Upload certificate
  _f5_upload_file "$upload_cert_src" "$remote_crt" "$host" "$insecure_flag" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    _f5_log err "Failed to upload certificate file to $host"
    return 2
  fi

  # 2. Install certificate (F5 creates object named $name.crt)
  _f5_install_object "$host" "cert" "$remote_crt" "$name" "$insecure_flag" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    _f5_log err "Failed to install certificate on $host"
    return 3
  fi

  # 3. Upload key
  _f5_upload_file "$_ckey" "$remote_key" "$host" "$insecure_flag" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    _f5_log err "Failed to upload key file to $host"
    return 4
  fi

  # 4. Install key (F5 creates object named $name.key)
  _f5_install_object "$host" "key" "$remote_key" "$name" "$insecure_flag" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    _f5_log err "Failed to install private key on $host"
    return 5
  fi

  # 5. Optionally update/create client-ssl profiles
  # Pass the base name; the function references the object name (no file extensions)
  if [ -n "$DEPLOY_F5_CLIENT_SSL" ]; then
    _f5_update_client_ssl "$host" "$partition" "$DEPLOY_F5_CLIENT_SSL" "$name" "$name" "$insecure_flag"
  fi

  _f5_log "F5 deploy for domain '$_domain' completed."
  return 0
}