/**
 * vectors/links-vectors.json (Record §8): the engine gives every
 * answer the file states, as a writer (`linksViolation`), as a reader holding
 * what each case's resolver lists (`checkLinks`), and as a capture's builder
 * (`buildLinks`). The Python half is tests/cross-sdk/test_links_vectors.py.
 */
import { LINK_RELATION_NAMES, buildLinks, checkLinks, linksViolation } from '@tzun/engine';
import { codeOf, resolverOf, vectorFile } from './vectors';

type Case = Record<string, any>;
const v = vectorFile<Record<string, any>>('links-vectors.json');
const groups = ['shapes', 'profiles', 'listLevel', 'targets'] as const;

describe('links vectors', () => {
  it('names the registry', () => expect(v.registry).toEqual([...LINK_RELATION_NAMES].sort()));
  for (const group of groups) {
    it.each(v[group] as Case[])(`${group}: $case`, (c) => {
      expect(codeOf(linksViolation(c.payload.links, c.payload))).toEqual(c.writer);
      expect(checkLinks(c.payload, { resolver: resolverOf(c.resolver) })).toEqual(c.reader);
    });
  }
  it.each(v.capture as Case[])('capture: $case', (c) => {
    const build = () =>
      buildLinks(c.inputs, { held: c.held, allowReserved: c.options.allowReserved, linkRecord: c.options.linkRecord, context: c.options.context });
    if (c.links !== undefined) expect(build()).toEqual(c.links);
    else expect(build).toThrow(expect.objectContaining(c.refused));
  });
});
