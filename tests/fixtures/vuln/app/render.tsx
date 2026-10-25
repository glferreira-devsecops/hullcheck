export function Note({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
