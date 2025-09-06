import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";

export function codeInjection(): ChainmailRivet {
  const codePatterns = [
    /\b(eval|exec|execfile|compile)\s*\(/i,
    /\b(import\s+os|import\s+subprocess|import\s+sys)\b/i,
    /\b(require\s*\(|module\.exports)\b/i,
    /<script[^>]*>|<\/script>/i,
    /\b(function\s*\(|=>\s*{|\$\{)/i,
    /\b(rm\s+-rf|del\s+\/|sudo\s+)/i,
    /\b(wget|curl|fetch)\s+http/i,
    /\b(__import__|getattr|setattr|hasattr)\s*\(/i,
    /\b(process\.env|process\.exit|process\.kill)/i,
    /\b(setTimeout|setInterval)\s*\(/i,
    /\bnew\s+Function\s*\(/i,
    /\bimport\s*\(/i,
    /\b(child_process|fs\.unlink|fs\.rmdir)\b/i,
    /\b(sh\s+-c|bash\s+-c|cmd\s+\/c|powershell\s+-c)\b/i,
    /\b(system\s*\(|popen\s*\(|shell_exec\s*\()\b/i,
    /\b(os\.system|subprocess\.call|subprocess\.run)\b/i,
    /\b(cat\s+\/etc\/passwd|ls\s+-la|ps\s+aux|netstat\s+-an)\b/i,
    /\b(whoami|id|uname\s+-a|pwd|env)\b/i,
    /\b(chmod\s+\+x|chown\s+|mount\s+|umount\s+)\b/i,
    /\b(nc\s+-|ncat\s+-|telnet\s+|ssh\s+)\b/i,
    /\b(iptables\s+|firewall\s+|selinux\s+)\b/i,
    /\b(crontab\s+-|at\s+now|systemctl\s+)\b/i,
    /\b(find\s+.*-exec|xargs\s+.*rm|grep\s+-r)\b/i,
    /\b(tar\s+-|zip\s+-|unzip\s+-|gzip\s+-)\b/i,
    /\b(kill\s+-9|killall\s+|pkill\s+)\b/i,
    /\b(nohup\s+|screen\s+-|tmux\s+)\b/i,
    /\b(dd\s+if=|fdisk\s+-|mkfs\s+)\b/i,
    /\b(echo\s+.*>\s*\/|cat\s+.*>\s*\/)\b/i,
    /\b(\|\s*sh|\|\s*bash|\|\s*zsh)\b/i,
    /\b(`[^`]*`|\$\([^)]*\))\b/i,
  ];

  return async (context, next) => {
    for (const pattern of codePatterns) {
      if (pattern.test(context.sanitized)) {
        context.flags.push(SecurityFlag.CODE_INJECTION);
        applyThreatPenalty(context, ThreatLevel.CRITICAL);
        context.metadata.codePattern = pattern.toString();
        break;
      }
    }
    return next();
  };
}
