// Type declarations for static asset imports via wrangler module rules
declare module '*.txt' {
  const content: string;
  export default content;
}

declare module '*.svg' {
  const content: string;
  export default content;
}

declare module '*.ico' {
  const content: ArrayBuffer;
  export default content;
}

declare module '*.jpg' {
  const content: ArrayBuffer;
  export default content;
}

declare module '*.png' {
  const content: ArrayBuffer;
  export default content;
}