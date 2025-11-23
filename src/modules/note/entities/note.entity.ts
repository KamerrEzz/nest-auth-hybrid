export interface NoteEntity {
  id: string;
  userId: string;
  title: string;
  content: string;
  secure: boolean;
  createdAt: number;
  updatedAt: number;
}
