/**
 * Agent descriptors for the agent catalog suites: the worked-example vectors
 * (vectors/v1.0-worked-example-vectors.json, `agentDescriptors`) and a
 * builder of distinct descriptors.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AgentDescriptor } from '@tzun/engine';

export interface AgentDescriptorVector {
  label: string;
  descriptor: AgentDescriptor;
  canonical: string;
  byteLength: number;
  digest: string;
}

/** The vector file's agent descriptors. */
export function vectorDescriptors(): AgentDescriptorVector[] {
  const file = JSON.parse(readFileSync(join(__dirname, '..', '..', '..', 'vectors', 'v1.0-worked-example-vectors.json'), 'utf8'));
  return file.agentDescriptors as AgentDescriptorVector[];
}

/** The worked example's first agent descriptor (a model-bearing agent), digest `sha256:eed92bfa…250f`. */
export const X12: AgentDescriptor = vectorDescriptors()[0].descriptor;

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

/** A distinct descriptor per `(name, organization, i)`, naming one model. */
export function descriptorNamed(name: string, organization: string, i: number): AgentDescriptor {
  return {
    v: 'tzun-agent/1',
    name,
    operator: { organization, owner: null },
    identities: [`spiffe://agents.example/${name}/${i}`],
    keys: [],
    models: [`sha256:${hex(`model ${i}`)}`],
    instructions: null,
    tools: null,
    runtime: null,
    policy: null,
    parent: null,
    derivation: null,
  };
}

/** A policy engine's descriptor: it names no model. */
export function policyEngineDescriptor(name = 'meridian-traffic-generator'): AgentDescriptor {
  return { ...descriptorNamed(name, 'Example Org', 0), models: [] };
}
