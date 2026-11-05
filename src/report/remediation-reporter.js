import path from 'node:path';
import fs from 'node:fs';
export { generateRemediationPlan } from '../core/remediation-planner.js';

export function writeRemediationPlan(plan, outputDir, filename = 'security-remediation-plan.json') {
  fs.mkdirSync(outputDir, { recursive: true });
  const targetPath = path.resolve(outputDir, filename);
  fs.writeFileSync(targetPath, JSON.stringify(plan, null, 2) + '\n', 'utf8');
  return targetPath;
}
