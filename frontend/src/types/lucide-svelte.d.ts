declare module 'lucide-svelte' {
    import { SvelteComponentTyped } from 'svelte';

    export class User extends SvelteComponentTyped<{ size?: number | string; class?: string; }> {}
    export class LogOut extends SvelteComponentTyped<{ size?: number | string; class?: string; }> {}
    export class Settings extends SvelteComponentTyped<{ size?: number | string; class?: string; }> {}
}
