import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import {
  createProfile,
  deleteProfile,
  setActiveProfile,
} from "@/lib/api";
import type { Registry } from "@/lib/types";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface Props {
  registry: Registry;
  onChange: (registry: Registry) => void;
}

export function ProfileBar({ registry, onChange }: Props) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const activeId = registry.activeProfileId ?? registry.profiles[0]?.id;

  async function handleSwitch(id: string) {
    try {
      onChange(await setActiveProfile(id));
    } catch (e) {
      toast.error(`Couldn't switch profile: ${e}`);
    }
  }

  async function handleCreate() {
    const trimmed = name.trim();
    if (!trimmed) return;
    try {
      onChange(await createProfile(trimmed));
      toast.success(`Created profile "${trimmed}"`);
      setName("");
      setOpen(false);
    } catch (e) {
      toast.error(`Couldn't create profile: ${e}`);
    }
  }

  async function handleDelete() {
    if (registry.profiles.length <= 1 || !activeId) return;
    try {
      onChange(await deleteProfile(activeId));
    } catch (e) {
      toast.error(`Couldn't delete profile: ${e}`);
    }
  }

  return (
    <div className="flex items-center gap-1.5">
      <Select value={activeId} onValueChange={handleSwitch}>
        <SelectTrigger size="sm" className="flex-1">
          <SelectValue placeholder="Profile" />
        </SelectTrigger>
        <SelectContent>
          {registry.profiles.map((p) => (
            <SelectItem key={p.id} value={p.id}>
              {p.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Button
        variant="ghost"
        size="icon"
        className="size-8 shrink-0"
        aria-label="New profile"
        onClick={() => setOpen(true)}
      >
        <Plus className="size-4" />
      </Button>

      {registry.profiles.length > 1 && (
        <Button
          variant="ghost"
          size="icon"
          className="size-8 shrink-0 text-muted-foreground hover:text-destructive"
          aria-label="Delete current profile"
          onClick={handleDelete}
        >
          <Trash2 className="size-4" />
        </Button>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>New profile</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-2 py-2">
            <Label htmlFor="profile-name">Name</Label>
            <Input
              id="profile-name"
              value={name}
              autoFocus
              placeholder="Work"
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleCreate();
              }}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={!name.trim()}>
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
