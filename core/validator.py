import requests
import urllib.parse
from typing import Dict, Any, List

class TargetValidator:
    """Step 2: Validates website reachability, HTTPS status, redirect chain, and HTTP status code."""
    
    @staticmethod
    def validate_url(url: str, timeout: int = 10) -> Dict[str, Any]:
        result = {
            "valid": False,
            "original_url": url,
            "final_url": url,
            "is_reachable": False,
            "is_https": False,
            "status_code": None,
            "redirect_chain": [],
            "error": None
        }
        
        # Ensure scheme is present
        target = url.strip()
        if not (target.startswith("http://") or target.startswith("https://")):
            target = "https://" + target
            
        try:
            # Send HTTP request with User-Agent header
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            
            response = requests.get(target, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
            
            result["is_reachable"] = True
            result["status_code"] = response.status_code
            result["final_url"] = response.url
            result["is_https"] = response.url.startswith("https://")
            
            # Extract redirect chain if any
            redirects: List[str] = [res.url for res in response.history]
            if redirects:
                redirects.append(response.url)
                result["redirect_chain"] = redirects
            else:
                result["redirect_chain"] = [target]
                
            # Reachable if status code is < 400 or auth-protected (401/403) or Cloudflare rate-limited (429)
            if response.status_code < 400 or response.status_code in [401, 403, 429]:
                result["valid"] = True
            else:
                result["error"] = f"HTTP Error Status: {response.status_code}"
                
        except requests.exceptions.SSLError:
            # Fallback check if SSL issue but site exists
            result["error"] = "SSL Verification Failed (Non-HTTPS or invalid certificate)"
            result["is_https"] = False
        except requests.exceptions.RequestException as e:
            error_str = str(e)
            if "ConnectionResetError" in error_str or "Connection aborted" in error_str or "RemoteDisconnected" in error_str or "Read timed out" in error_str:
                # WAF / Anti-Bot protection is likely blocking the 'requests' library. 
                # We should still allow Playwright to attempt to load the site.
                result["valid"] = True
                result["error"] = f"WAF Blocked Validator (Connection Reset). Proceeding to browser..."
                result["is_reachable"] = True
            else:
                result["error"] = f"Connection Failed: {error_str}"
                result["is_reachable"] = False
            
        return result
