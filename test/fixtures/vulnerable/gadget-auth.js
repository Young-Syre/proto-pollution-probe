// PP-G04: the condition a permission check rests on is a property nothing assigns.
export function assertCanPublish(session) {
  if (session.isAdmin) {
    return;
  }
  if (session.permissions) {
    return;
  }
  throw new Error('not permitted');
}
