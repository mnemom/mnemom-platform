import yaml from 'js-yaml';
import type { Policy } from './types.js';

export function loadFromYAML(yamlString: string): Policy {
  return yaml.load(yamlString) as Policy;
}

export function toYAML(policy: Policy): string {
  return yaml.dump(policy);
}
